import { Polynomial } from "./polynomial";
import { DistributionSharesBox, Point, Share } from "./types";
import { G1, Hx, Hy, theCurve, theCurveN } from "./params";
import { randomBytes } from "@noble/hashes/utils";
import { DLEQ } from "./dleq";
import { sha3_256 } from "@noble/hashes/sha3";
import { p256 } from "@noble/curves/p256";

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
    const hasher = sha3_256.create()

    for (const a_j of poly.coefficients) {
      const { x, y } = H.multiply(a_j);
      commitments.push(new Point(x, y));

    }
    for (const share of shares) {
      const pi = poly.getValue(BigInt(share.position), theCurveN);
      const wi = BigInt('0x' + Buffer.from(randomBytes(32)).toString('hex')); // Generate random BigInt
      const { px, py } = p256.ProjectivePoint.fromHex(share.pk)
      const dleq = new DLEQ(H, new Point(px, py), wi, pi);
      share.S = dleq.H2;
      const { c, r } = dleq.challengeAndResponse();

      share.challenge = c;
      share.response = r;
    }

    // FIXME: I don't think this is right...
    const p = theCurve.ProjectivePoint.BASE.multiply(poly.coefficients[0]);
    hasher.update(p.toRawBytes());

    const hash256 = hasher.digest();
    const u = secret ^ BigInt('0x' + Buffer.from(hash256).toString('hex'));

    return {
      Commitments: commitments,
      Shares: shares,
      U: u,
    };
  }
}

export function VerifyDistributionShares(sharesBox: DistributionSharesBox): boolean {
    if (!sharesBox || !sharesBox.Shares || !sharesBox.Commitments) {
        console.error('Invalid sharesBox');
        return false;
    }

    const hasher = sha3_256.create();

    const Cj = sharesBox.Commitments;

    for (const share of sharesBox.Shares) {
        let Xix = BigInt(Cj[0].x);
        let Xiy = BigInt(Cj[0].y);

        for (let j = 1; j < Cj.length; j++) {
            const bigi = BigInt(share.position);
            const bigj = BigInt(j);
            const bigij = bigi ** bigj % theCurveN; // i^j mod N

            const Cij = Cj[j].multiply(bigij); // Check if this multiplication is correct

            Xix = (Xix + BigInt(Cij.x)) % BigInt(theCurve.CURVE.p);
            Xiy = (Xiy + BigInt(Cij.y)) % BigInt(theCurve.CURVE.p);
        }

        const H = new Point(Hx, Hy);
        const { px, py } = p256.ProjectivePoint.fromHex(share.pk);
        const ok = DLEQ.verify(
            H,
            new Point(Xix, Xiy),
            new Point(px, py),
            share.S,
            share.challenge,
            share.response
        );

        if (!ok) {
            console.error('Verification failed for share:', share);
            return false;
        }
    }
    return true;
}

