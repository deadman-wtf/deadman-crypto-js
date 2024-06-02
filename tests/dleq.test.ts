import { p256 } from "@noble/curves/p256";
import { DLEQ } from "../src/dleq"
import { G1, G2, Hx, Hy, theCurveN } from "../src/params";
import { bigIntFromUint8Array, getRandomBigInt } from "../src/util";
import { sha3_256 } from "@noble/hashes/sha3";
import { Point } from "../src/types";

test('DLEQ::new', () => {
  const priv = p256.utils.randomPrivateKey();
  const {x, y} = p256.ProjectivePoint.fromPrivateKey(priv)
  const h2 = p256.ProjectivePoint.fromAffine({x: Hx, y: Hy}).multiply(bigIntFromUint8Array(priv));
  const dleq = new DLEQ(G1, null, G2, null, getRandomBigInt(theCurveN), bigIntFromUint8Array(priv))
  expect(true).toBe(dleq.H1.x == x);
  expect(true).toBe(dleq.H1.y == y);
  expect(true).toBe(dleq.H2.x == h2.x);
  expect(true).toBe(dleq.H2.y == h2.y);
});

function privateKeyToBigInt(priv: Uint8Array): bigint {
  const privateKeyHex = Buffer.from(priv).toString('hex');
  const privateKeyBigInt = BigInt('0x' + privateKeyHex);
  return privateKeyBigInt;
}

test('DLEQ::verify', () => {
  const d = privateKeyToBigInt(p256.utils.randomPrivateKey());
  const w = getRandomBigInt(theCurveN);
  const dleq = new DLEQ(G1, null, G2, null, w, d);
  const { c, r } = dleq.challengeAndResponse();
  const hasher = sha3_256.create();
  const ok = DLEQ.verify(dleq.G1, dleq.H1, dleq.G2, dleq.H2, c, r)
  expect(ok).toBeTruthy();
});

test('DLEQ::hash', () => {
  // Expected sha3-256 digest of hash updated with values [0, 0, 0]
  const expected = new Uint8Array([167, 255, 198, 248, 191, 30, 215, 102, 81, 193, 71, 86, 160, 97, 214, 98, 245, 128, 255, 77, 228, 59, 73, 250, 130, 216, 10, 75, 128, 248, 67, 74]);
  const actual = DLEQ.hash(0n, 0n, 0n);
  expect(actual).toEqual(expected);

});

test('DLEQ::hashMod', () => {
  const expected = BigInt("5404410")
  const hasher = sha3_256.create();
  const actual = DLEQ.hashMod(BigInt("10333301"), BigInt("10333301"), BigInt("10333301"), BigInt("10333301"))
  expect(actual).toEqual(expected)
});

