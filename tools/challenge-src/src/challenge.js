import blake3 from "../node_modules/blake3-bao/blake3.js";

const BLAKE3_HASH_BITS = 256;
const CHALLENGE_SEED_LENGTH = 32;
const INSTRUMENTATION_RESULT_HEX_LEN = 64;

function fromHex(hex) {
    if (
        typeof hex !== "string" ||
        hex.length % 2 !== 0 ||
        !/^[0-9a-fA-F]*$/.test(hex)
    ) {
        throw new Error("ungueltiger Hex-Wert");
    }

    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i += 1) {
        out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
}

function fromBase64Url(value) {
    if (typeof value !== "string" || value.length === 0) {
        throw new Error("ungueltiger Base64URL-Wert");
    }

    const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
    const pad = (4 - (base64.length % 4)) % 4;
    const normalized = base64 + "=".repeat(pad);
    const binary = atob(normalized);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
        out[i] = binary.charCodeAt(i);
    }
    return out;
}

function toHex(bytes) {
    let out = "";
    for (const value of bytes) {
        out += value.toString(16).padStart(2, "0");
    }
    return out;
}

function incrementNonce(nonce) {
    for (let i = nonce.length - 1; i >= 0; i -= 1) {
        nonce[i] = (nonce[i] + 1) & 0xff;
        if (nonce[i] !== 0) {
            return;
        }
    }
}

function safeReturnTo(value) {
    if (
        typeof value === "string" &&
        value.startsWith("/") &&
        !value.startsWith("//")
    ) {
        return value;
    }
    return window.location.href;
}

function leadingZeroBits(bytes) {
    let count = 0;
    for (const value of bytes) {
        if (value === 0) {
            count += 8;
            continue;
        }
        for (let bit = 7; bit >= 0; bit -= 1) {
            if ((value & (1 << bit)) === 0) {
                count += 1;
                continue;
            }
            return count;
        }
    }
    return count;
}

function setStatus(node, message) {
    if (node) {
        node.textContent = message;
    }
}

function parseChallengeToken(challengeToken) {
    if (typeof challengeToken !== "string" || challengeToken.length === 0) {
        throw new Error("ungueltiges Challenge-Token");
    }

    const [payloadPart] = challengeToken.split(".", 1);
    if (!payloadPart) {
        throw new Error("ungueltiges Challenge-Token");
    }

    const claims = JSON.parse(
        new TextDecoder().decode(fromBase64Url(payloadPart)),
    );
    if (!claims || typeof claims.seed !== "string") {
        throw new Error("ungueltiges Challenge-Token");
    }
    return claims;
}

function deriveInstrumentationSpec(seed) {
    if (
        !(seed instanceof Uint8Array) ||
        seed.length !== CHALLENGE_SEED_LENGTH
    ) {
        throw new Error("ungueltiger Instrumentation-Seed");
    }

    const saltView = new DataView(seed.buffer, seed.byteOffset + 6, 4);
    return {
        treeDepth: 3 + (seed[0] % 4),
        treeBase: 11 + (seed[1] % 19),
        treeStep: 1 + (seed[2] % 7),
        attrCount: 3 + (seed[3] % 5),
        attrBase: 2 + (seed[4] % 17),
        typedRounds: 4 + (seed[5] % 4),
        typedSalt: (saltView.getUint32(0, false) ^ 0x9e3779b9) >>> 0,
    };
}

function instrumentationTreeAccumulator(spec) {
    const host = document.createElement("div");
    host.hidden = true;
    host.setAttribute("data-cp-instrument", "tree");
    document.body.appendChild(host);

    let parent = host;
    for (let level = 0; level < spec.treeDepth; level += 1) {
        const node = document.createElement(level % 2 === 0 ? "div" : "span");
        const value = (spec.treeBase + level * spec.treeStep) & 0xff;
        node.dataset.value = String(value);
        node.setAttribute(
            "data-branch",
            String((value ^ spec.attrBase) & 0x1f),
        );
        parent.appendChild(node);
        parent = node;
    }

    let sum = 0;
    let cursor = parent;
    let level = 0;
    while (cursor && cursor !== host) {
        sum =
            (sum +
                Number(cursor.dataset.value || 0) +
                cursor.attributes.length +
                level) >>>
            0;
        cursor = cursor.parentElement;
        level += 1;
    }

    host.remove();
    return sum >>> 0;
}

function instrumentationAttributeAccumulator(seed, spec) {
    const host = document.createElement("div");
    host.hidden = true;
    host.setAttribute("data-cp-instrument", "attrs");

    for (let i = 0; i < spec.attrCount; i += 1) {
        const node = document.createElement("span");
        const b = seed[(10 + i) % seed.length];
        const textLength = 3 + (b % 5);
        const marker = (spec.attrBase + b) % 11;
        node.setAttribute("data-cp-probe", String(marker));
        node.dataset.index = String(i);
        node.textContent = String.fromCharCode(97 + (b % 26)).repeat(
            textLength,
        );
        host.appendChild(node);
    }

    document.body.appendChild(host);

    let sum = 0;
    const nodes = host.querySelectorAll("[data-cp-probe]");
    nodes.forEach((node) => {
        sum =
            (sum +
                (node.textContent ? node.textContent.length : 0) +
                node.attributes.length +
                Number(node.dataset.index || 0) +
                Number(node.getAttribute("data-cp-probe") || 0)) >>>
            0;
    });

    host.remove();
    return sum >>> 0;
}

function instrumentationTypedAccumulator(seed, spec) {
    const view = new DataView(seed.buffer, seed.byteOffset, 16);
    let acc = spec.typedSalt >>> 0;

    for (let i = 0; i < 4; i += 1) {
        const word = view.getUint32(i * 4, false);
        const rotation = (spec.typedRounds + i) % 32 || 1;
        const mixed =
            (((acc ^ word ^ (((i + 1) * 0x45d9f3b) >>> 0)) << rotation) |
                ((acc ^ word ^ (((i + 1) * 0x45d9f3b) >>> 0)) >>>
                    (32 - rotation))) >>>
            0;
        acc = (mixed + spec.treeBase + i * 17) >>> 0;
    }

    return acc >>> 0;
}

function buildInstrumentationPayload(seed, spec, tree, attrs, typed) {
    const payload = new Uint8Array(36);
    const view = new DataView(payload.buffer);
    view.setUint32(0, tree >>> 0, false);
    view.setUint32(4, attrs >>> 0, false);
    view.setUint32(8, typed >>> 0, false);
    view.setUint32(12, spec.treeDepth >>> 0, false);
    view.setUint32(16, spec.treeBase >>> 0, false);
    view.setUint32(20, spec.treeStep >>> 0, false);
    view.setUint32(24, spec.attrCount >>> 0, false);
    view.setUint32(28, spec.attrBase >>> 0, false);
    view.setUint32(32, spec.typedRounds >>> 0, false);
    return payload;
}

async function runInstrumentation(seedHex, statusNode) {
    setStatus(statusNode, "Browser-Umgebung wird geprueft...");

    const startedAt = performance.now();
    const hasDOM =
        typeof document === "object" &&
        !!document.body &&
        typeof document.createElement === "function";
    const hasCrypto =
        typeof crypto === "object" &&
        !!crypto &&
        typeof crypto.getRandomValues === "function";
    const hasRAF = typeof requestAnimationFrame === "function";
    const webdriver =
        typeof navigator === "object" &&
        !!navigator &&
        navigator.webdriver === true;

    if (!hasDOM || !hasCrypto || !hasRAF) {
        throw new Error("Browser-APIs fuer Instrumentation fehlen");
    }

    const seed = fromHex(seedHex);
    const spec = deriveInstrumentationSpec(seed);

    const tree = instrumentationTreeAccumulator(spec);
    await new Promise((resolve) => requestAnimationFrame(resolve));
    const attrs = instrumentationAttributeAccumulator(seed, spec);
    const typed = instrumentationTypedAccumulator(seed, spec);
    const payload = buildInstrumentationPayload(seed, spec, tree, attrs, typed);
    const result = toHex(blake3.hash(payload));

    if (result.length !== INSTRUMENTATION_RESULT_HEX_LEN) {
        throw new Error("Instrumentation-Ergebnis hat ungueltige Laenge");
    }

    return {
        result,
        durationMs: Math.max(0, Math.round(performance.now() - startedAt)),
        hasDom: hasDOM,
        hasCrypto,
        hasRaf: hasRAF,
        webdriver,
    };
}

async function solveChallenge(config, statusNode) {
    if (!config || typeof config !== "object") {
        throw new Error("ungueltige Challenge-Konfiguration");
    }

    const { challengeToken, complexity, verifyPath } = config;
    if (
        !Number.isInteger(complexity) ||
        complexity < 0 ||
        complexity > BLAKE3_HASH_BITS
    ) {
        throw new Error("ungueltige Complexity");
    }

    if (typeof blake3.initSimd === "function") {
        try {
            await blake3.initSimd();
        } catch (_) {
            // Reiner-JS-Fallback ist ausreichend, wenn SIMD nicht initialisiert werden kann.
        }
    }

    const claims = parseChallengeToken(challengeToken);
    const seed = fromHex(claims.seed);
    const instrumentation = claims.instrumentation
        ? await runInstrumentation(claims.seed, statusNode)
        : null;
    const nonce = new Uint8Array(16);
    const input = new Uint8Array(seed.length + nonce.length);
    input.set(seed, 0);
    crypto.getRandomValues(nonce);
    let lastYield = performance.now();

    setStatus(statusNode, "Challenge wird geloest...");

    while (true) {
        incrementNonce(nonce);
        input.set(nonce, seed.length);

        const hash = blake3.hash(input);
        if (leadingZeroBits(hash) >= complexity) {
            setStatus(statusNode, "Challenge wird verifiziert...");

            const body = {
                challengeToken,
                nonce: toHex(nonce),
            };
            if (instrumentation) {
                body.instrumentation = instrumentation;
            }

            const response = await fetch(verifyPath, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify(body),
            });

            if (!response.ok) {
                throw new Error(
                    `Verifikation mit Status ${response.status} fehlgeschlagen`,
                );
            }

            const json = await response.json();
            window.location.replace(safeReturnTo(json.returnTo));
            return;
        }

        const now = performance.now();
        if (now - lastYield >= 16) {
            lastYield = now;
            await new Promise((resolve) => requestAnimationFrame(resolve));
        }
    }
}

export { solveChallenge };
