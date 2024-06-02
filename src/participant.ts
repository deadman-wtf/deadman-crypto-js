import { Polynomial } from "./polynomial";
import { DistributionSharesBox, Point, Share } from "./types";
import { G1, Hx, Hy, theCurve, theCurveN } from "./params";
import { randomBytes } from "@noble/hashes/utils";
import { DLEQ } from "./dleq";
import { sha3_256 } from "@noble/hashes/sha3";
import { p256 } from "@noble/curves/p256";
import { bigIntToBytes } from "./util"

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
