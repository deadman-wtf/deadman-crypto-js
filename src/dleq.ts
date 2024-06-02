import { p256 } from '@noble/curves/p256';
import { sha256 } from '@noble/hashes/sha256';
import { randomBytes } from '@noble/hashes/utils';
import { Point } from './types';
import { theCurveN } from './params';

// DLEQ class implementing the protocol
export class DLEQ {
    G1: Point;
    H1: Point;
    G2: Point;
    H2: Point;
    w: bigint;
    alpha: bigint;
    r: bigint | null;

    constructor(G1: Point, G2: Point, w: bigint, alpha: bigint) {
        const n = p256.CURVE.n;

        if (w <= 0n || w >= n) throw new Error('w must be in the range 0 < w < curveN');
        if (alpha <= 0n || alpha >= n) throw new Error('alpha must be in the range 0 < alpha < curveN');

        this.G1 = G1;
        this.G2 = G2;
        this.w = w;
        this.alpha = alpha;
        this.r = null;

        // Calculate H1 = alpha * G1 and H2 = alpha * G2 if not provided
        this.H1 = this.G1.multiply(alpha);
        this.H2 = this.G2.multiply(alpha);
    }

    static toHex(num: bigint): string {
        return num.toString(16).padStart(64, '0');
    }

    static hash(...inputs: bigint[]): bigint {
        const inputHex = inputs.map(DLEQ.toHex).join('');
        const hashOutput = sha256(new TextEncoder().encode(inputHex));
        return BigInt('0x' + Buffer.from(hashOutput).toString('hex'));
    }

    static response(w: bigint, alpha: bigint, c: bigint, n: bigint): bigint {
        let r = (alpha * c) % n; // alpha * c mod n
        r = (w - r + n) % n;     // (w - alpha * c + n) mod n to handle negative results
        return r;
    }

    challengeAndResponse(): { c: bigint, r: bigint } {
        const n = p256.CURVE.n;

        // A1 := w·G1 , A2 := w·G2
        const A1 = this.G1.multiply(this.w);
        const A2 = this.G2.multiply(this.w);

        // c := Hash(H1,H2,A1,A2) mod n
        const c = DLEQ.hash(this.H1.x, this.H1.y, this.H2.x, this.H2.y, A1.x, A1.y, A2.x, A2.y) % n;

        if (c <= 0n || c >= n) throw new Error('c must be in the range 0 < c < n');

        // r := (w - alpha * c) mod n
        const r = DLEQ.response(this.w, this.alpha, c, n);

        return { c, r };
    }

    static verify(G1: Point, H1: Point, G2: Point, H2: Point, c: bigint, r: bigint): boolean {
        const n = p256.CURVE.n;

        if (c <= 0n || c >= n) throw new Error('c must be in the range 0 < c < n');
        if (r <= 0n || r >= n) throw new Error('r must be in the range 0 < r < n');

        // Calculate A1 = r·G1 + c·H1
        const A1 = G1.multiply(r).add(H1.multiply(c));

        // Calculate A2 = r·G2 + c·H2
        const A2 = G2.multiply(r).add(H2.multiply(c));

        // Calculate the local challenge
        const localChallenge = DLEQ.hash(H1.x, H1.y, H2.x, H2.y, A1.x, A1.y, A2.x, A2.y) % n;

        return localChallenge === c;
    }
}

