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
  const dleq = new DLEQ(G1, G2, getRandomBigInt(theCurveN), bigIntFromUint8Array(priv))
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
  const dleq = new DLEQ(G1, G2, w, d);
  const { c, r } = dleq.challengeAndResponse();
  const ok = DLEQ.verify(dleq.G1, dleq.H1, dleq.G2, dleq.H2, c, r)
  expect(ok).toBeTruthy();
});
