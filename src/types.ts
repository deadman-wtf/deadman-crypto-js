import { p256 } from "@noble/curves/p256";

// Define a Point class for better type safety and utility methods
export class Point {
    x: bigint;
    y: bigint;

    constructor(x: bigint, y: bigint) {
        this.x = x;
        this.y = y;
    }

    static fromNoble(point: any): Point {
        return new Point(BigInt(point.x), BigInt(point.y));
    }

    toNoble() {
        return { x: this.x, y: this.y };
    }

    multiply(scalar: bigint): Point {
        const result = p256.ProjectivePoint.fromAffine(this.toNoble()).multiply(scalar);
        return Point.fromNoble(result.toAffine());
    }

    add(point: Point): Point {
        const result = p256.ProjectivePoint.fromAffine(this.toNoble()).add(p256.ProjectivePoint.fromAffine(point.toNoble()));
        return Point.fromNoble(result.toAffine());
    }
}

export interface Share {
  pk: Uint8Array;
  position: number;
  S?: Point;
  challenge?: bigint;
  response?: bigint;
}

export interface DistributionSharesBox {
  Commitments: Point[];
  Shares: Share[];
  U: bigint;
}
