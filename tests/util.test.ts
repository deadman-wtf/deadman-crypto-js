import { bigIntFromUint8Array, bigIntToBytes, hash, hashMod } from "../src/util";
import { sha3_256 } from "@noble/hashes/sha3";

test('util::hash', () => {
  // Expected sha3-256 digest of hash updated with values [0, 0, 0]
  const expected = Buffer.from([167, 255, 198, 248, 191, 30, 215, 102, 81, 193, 71, 86, 160, 97, 214, 98, 245, 128, 255, 77, 228, 59, 73, 250, 130, 216, 10, 75, 128, 248, 67, 74]).toString('hex');
  const actual = hash(sha3_256.create(), 0n, 0n, 0n);
  expect(actual).toEqual(expected);

});

test('util::hashMod', () => {
  const expected = BigInt("5404410")
  const actual = hashMod(BigInt("10333301"), sha3_256.create(), BigInt("10333301"), BigInt("10333301"), BigInt("10333301"))
  expect(actual).toEqual(expected)
});

test('util::bigIntFromUint8Array', () => {});

test('util::bigIntToBytes', () => {
  const test = BigInt(10333301);
  const bytes = bigIntToBytes(test);
  const recreated = bigIntFromUint8Array(bytes)
  expect(bytes).toEqual(Uint8Array.from([ 157, 172, 117 ]))
  expect(recreated).toEqual(test)
  console.log(test, bytes, recreated)
});

