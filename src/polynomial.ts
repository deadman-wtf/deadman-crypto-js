import { getRandomBigInt } from "./util";

// Polynomial class
export class Polynomial {
  coefficients: bigint[];

  constructor(degree: number, n: bigint) {
    this.coefficients = [];

    for (let i = 0; i <= degree; i++) {
      const a = getRandomBigInt(n);
      this.coefficients.push(a);
    }
  }

  getValue(x: bigint, n: bigint): bigint {
    let result = BigInt(0);
    let power = BigInt(1);

    for (const coefficient of this.coefficients) {
      result = (result + coefficient * power) % n;
      power = (power * x) % n;
    }

    return result;
  }
}
