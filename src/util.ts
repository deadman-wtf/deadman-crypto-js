export const randomString = (length: number) => {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let result = "";
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

export function bigIntToBytes(bigint: bigint): Uint8Array {
  const hexString = bigint.toString(16);
  const bytes = new Uint8Array(hexString.length / 2);

  for (let i = 0; i < hexString.length / 2; i++) {
    bytes[i] = parseInt(hexString.slice(i * 2, i * 2 + 2), 16);
  }

  return bytes;
}

// Function to recreate a BigInt from a Uint8Array
export function bigIntFromUint8Array(uint8Array: Uint8Array): bigint {
  const hexString = Array.from(uint8Array).map(byte => byte.toString(16).padStart(2, '0')).join('');
  return BigInt('0x' + hexString);
}

export function getRandomBigInt(maxValue: bigint): bigint {
  // Determine the number of bytes required to represent the maximum value
  const maxLength = (maxValue.toString(16).length + 1) / 2;

  let randomValue;
  do {
    // Generate random bytes
    const buffer = new Uint8Array(maxLength);
    crypto.getRandomValues(buffer);

    // Convert bytes to a hexadecimal string
    const hexString = Array.from(buffer).map(byte => byte.toString(16).padStart(2, '0')).join('');

    // Convert hexadecimal string to a BigInt
    randomValue = BigInt('0x' + hexString);
  } while (randomValue >= maxValue);

  return randomValue;
}

