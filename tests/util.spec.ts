import { bigIntFromUint8Array, bigIntToBytes } from "../src/util";

test('util::bigIntFromUint8Array', () => {});

test('util::bigIntToBytes', () => {
  const test = BigInt(10333301);
  const bytes = bigIntToBytes(test);
  const recreated = bigIntFromUint8Array(bytes)
  expect(bytes).toEqual(Uint8Array.from([ 157, 172, 117 ]))
  expect(recreated).toEqual(test)
  console.log(test, bytes, recreated)
});

