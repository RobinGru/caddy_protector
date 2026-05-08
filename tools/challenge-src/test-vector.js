import blake3 from "./node_modules/blake3-bao/blake3.js";

const seedHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const nonceHex = "000102030405060708090a0b0c0d0e0f";
const expected = "c69e86514b4b59e4a7296fc05db8f4c1dd17825679f25d97d285b970aa2ea853";

const input = Buffer.concat([
  Buffer.from(seedHex, "hex"),
  Buffer.from(nonceHex, "hex")
]);

const got = blake3.toHex(blake3.hash(input));
if (got !== expected) {
  throw new Error(`unerwarteter Testvektor: ${got} != ${expected}`);
}

console.log("BLAKE3-Testvektor erfolgreich geprüft.");
