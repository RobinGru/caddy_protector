import blake3 from "../node_modules/blake3-bao/blake3.js";

const BLAKE3_HASH_BITS = 256;

function fromHex(hex) {
  if (typeof hex !== "string" || hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error("ungültiger Hex-Wert");
  }

  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
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
  if (typeof value === "string" && value.startsWith("/") && !value.startsWith("//")) {
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

async function solveChallenge(seedHex, complexity, verifyPath, statusNode) {
  if (!Number.isInteger(complexity) || complexity < 0 || complexity > BLAKE3_HASH_BITS) {
    throw new Error("ungültige Complexity");
  }

  if (typeof blake3.initSimd === "function") {
    try {
      await blake3.initSimd();
    } catch (_) {
      // Reiner-JS-Fallback ist ausreichend, wenn SIMD nicht initialisiert werden kann.
    }
  }

  const seed = fromHex(seedHex);
  const nonce = new Uint8Array(16);
  const input = new Uint8Array(seed.length + nonce.length);
  input.set(seed, 0);
  crypto.getRandomValues(nonce);
  let lastYield = performance.now();

  setStatus(statusNode, "Challenge wird gelöst...");

  while (true) {
    incrementNonce(nonce);
    input.set(nonce, seed.length);

    const hash = blake3.hash(input);
    if (leadingZeroBits(hash) >= complexity) {
      setStatus(statusNode, "Challenge wird verifiziert...");

      const response = await fetch(verifyPath, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          seed: seedHex,
          nonce: toHex(nonce)
        })
      });

      if (!response.ok) {
        throw new Error(`Verifikation mit Status ${response.status} fehlgeschlagen`);
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
