import { Polynomial } from "./polynomial";
import { DecryptedShare, DistributionSharesBox, Point, Share } from "./types";
import { G1, Hx, Hy, theCurve, theCurveN } from "./params";
import { randomBytes } from "@noble/hashes/utils";
import { DLEQ } from "./dleq";
import { sha3_256 } from "@noble/hashes/sha3";
import { p256 } from "@noble/curves/p256";
import { bigIntFromUint8Array, bigIntToBytes, getRandomBigInt } from "./util"

export interface IParticipant {
  pk: Uint8Array
}

export interface IDealer extends IParticipant {
  privateKey: Uint8Array
}

export class Dealer implements IDealer {
  privateKey: Uint8Array;
  pk: Uint8Array;

  constructor(privateKey: Uint8Array) {
    this.privateKey = privateKey;
    this.pk = p256.getPublicKey(privateKey);
  }

  distributeSecret(secret: bigint, pks: Uint8Array[], threshold: number) {
    if (pks.length < threshold) {
      console.error(`length of public_keys(${pks.length}) < threshold(${threshold})>`)
    }

    const poly = new Polynomial(threshold-1, theCurveN);
    const shares: Share[] = [];
    for (var i = 0; i < pks.length; i++) {
      shares.push({
        pk: pks[i],
        position: i + 1
      })
    }
    return this.distribute(secret, shares, threshold, poly)
  }

  async distribute(secret: bigint, shares: Share[], threshold: number, poly: Polynomial): Promise<DistributionSharesBox> {
    const commitments: Point[] = [];
    const G = G1;
    const H = new Point(Hx, Hy);
    const hasher = sha3_256.create();

    for (const a_j of poly.coefficients) {
      const { x, y } = H.multiply(a_j);
      commitments.push(new Point(x, y));
    }

    for (const share of shares) {
      const pi = poly.getValue(BigInt(share.position), theCurveN);
      const wi = BigInt('0x' + Buffer.from(randomBytes(32)).toString('hex'));
      const { x: px, y: py } = theCurve.ProjectivePoint.fromHex(share.pk);
      const dleq = new DLEQ(H, null, new Point(px, py), null, wi, pi);
      share.S = dleq.H2;
      const { c, r } = dleq.challengeAndResponse();
      share.challenge = c;
      share.response = r;
    }

    const sG = theCurve.ProjectivePoint.BASE.multiply(poly.coefficients[0]);
    hasher.update(bigIntToBytes(sG.x));
    hasher.update(bigIntToBytes(sG.y));
    const hash256 = hasher.digest();
    const u = secret ^ BigInt('0x' + Buffer.from(hash256).toString('hex'));

    return {
      Commitments: commitments,
      Shares: shares,
      U: u,
    };
  }


  extractSecretShare(sharesBox: DistributionSharesBox): DecryptedShare | null {
    // Find share for the dealer itself
    // Find share for the dealer itself
    console.log('Dealer public key:', this.pk);
    sharesBox.Shares.forEach(s => {
      console.log('Share public key:', s.pk);
    });

    const share = sharesBox.Shares.find(s => 
      this.arraysEqual(s.pk, this.pk)
    );

    if (!share) {
      console.error("No share for me");
      return null;
    }

    return this.extractSecretShareInternal(share);
  }

  private extractSecretShareInternal(share: Share): DecryptedShare | null {
    // Decryption of the shares
    // Using its private key x_i, each participant finds the decrypted share S_i from Y_i by computing S_i = Y_i·(1/x_i mod N).
    const privateInverse = modInverse(BigInt(`0x${Buffer.from(this.privateKey).toString('hex')}`), theCurveN);

    const { x: six, y: siy } = share.S.multiply(privateInverse);

    // DLEQ(G, publickey, decrypted_share, encrypted_share)
    const w = getRandomBigInt(theCurveN);
    // TODO; there is your problem Hx
    const { x: px, y: py } = theCurve.ProjectivePoint.fromHex(share.pk);
    const dleq = new DLEQ(G1, new Point(px, py), new Point(six, siy), null, w, bigIntFromUint8Array(this.privateKey))
    const {c, r} = dleq.challengeAndResponse();
    return {
      PK: this.pk,
      Position: share.position,
      S: dleq.G2,
      Y: dleq.H2,
      challenge: c,
      response: r
    };
  }


  private arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) return false;
    }
    return true;
  }
}

export function verifyDistributionShares(sharesBox: DistributionSharesBox): boolean {
  if (!sharesBox || !sharesBox.Shares || !sharesBox.Commitments) {
    console.error('Invalid sharesBox');
    return false;
  }

  const Cj = sharesBox.Commitments;
  const H = new Point(Hx, Hy);

  for (const share of sharesBox.Shares) {
    // Initialize X_i with the first commitment
    let Xi = theCurve.ProjectivePoint.fromAffine(Cj[0]);

    for (let j = 1; j < Cj.length; j++) {
      const bigi = BigInt(share.position);
      const bigj = BigInt(j);
      const bigij = bigi ** bigj % theCurveN; // i^j mod N

      // Perform scalar multiplication and point addition
      const Cij = theCurve.ProjectivePoint.fromAffine(Cj[j]).multiply(bigij);
      Xi = Xi.add(Cij);
    }

    const { x: px, y: py } = theCurve.ProjectivePoint.fromHex(share.pk);
    const ok = DLEQ.verify(
      H,
      new Point(Xi.x, Xi.y),
      new Point(px, py),
      share.S,
      share.challenge,
      share.response
    );

    if (!ok) {
      console.error('Verification failed for share', share.position, share);
      return false;
    }
  }
  return true;
}

export function VerifyDecryptedShare(decShare: DecryptedShare): boolean {
  const { x: px, y: py } = theCurve.ProjectivePoint.fromHex(decShare.PK);
  return DLEQ.verify(
    G1,
    new Point(px, py),
    decShare.S,
    decShare.Y,
    decShare.challenge,
    decShare.response
  )
}

export function ReconstructSecret(decShares: DecryptedShare[], u: bigint): bigint {
  const bigjs = new Map<number, bigint>();
  for (const ds of decShares) {
    bigjs.set(ds.Position, BigInt(ds.Position));
  }

  // Initialize the sum to zero point
  let sum = theCurve.ProjectivePoint.ZERO;

  for (const ds of decShares) {
    // λ_i
    const lambda = lagrangeCoefficient(ds.Position, bigjs);

    const S = theCurve.ProjectivePoint.fromAffine({ x: ds.S.x, y: ds.S.y });

    const lambdaS = S.multiply(lambda); // Multiply point by scalar

    sum = sum.add(lambdaS); // Add the scaled point to the sum
  }

  // Compute sGx and sGy from the sum
  const sGx = sum.x;
  const sGy = sum.y;

  // Compute the hash of the sum of points
  const hash256 = sha3_256.create();
  hash256.update(bigIntToBytes(sGx));
  hash256.update(bigIntToBytes(sGy));
  const hashBytes = hash256.digest();
  const hashBigInt = BigInt('0x' + Buffer.from(hashBytes).toString('hex'));

  // Compute the secret using XOR operation
  const secret = u ^ hashBigInt;

  return secret;
}


// Function to compute Lagrange coefficient
function lagrangeCoefficient(i: number, bigjs: Map<number, bigint>): bigint {
  let numerator = BigInt(1);
  let denominator = BigInt(1);
  const bi = BigInt(i);

  for (const [j, bj] of bigjs.entries()) {
    if (j !== i) {
      numerator = (numerator * bj) % theCurveN;
      const jsubi = (bj - bi + theCurveN) % theCurveN;
      denominator = (denominator * jsubi) % theCurveN;
    }
  }

  const inverseDenom = modInverse(denominator, theCurveN);
  const lambda = (numerator * inverseDenom) % theCurveN;
  return lambda;
}

// Function to compute modular inverse
function modInverse(a: bigint, n: bigint): bigint {
  let t = BigInt(0);
  let newT = BigInt(1);
  let r = n;
  let newR = a;

  while (newR !== BigInt(0)) {
    const quotient = r / newR;
    [t, newT] = [newT, t - quotient * newT];
    [r, newR] = [newR, r - quotient * newR];
  }

  if (r > BigInt(1)) {
    throw new Error('a is not invertible');
  }
  if (t < BigInt(0)) {
    t = t + n;
  }
  return t;
}
