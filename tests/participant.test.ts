import { p256 } from "@noble/curves/p256";
import { DLEQ } from "../src/dleq"
import { G1, G2, Hx, Hy, theCurveN } from "../src/params";
import { bigIntFromUint8Array, getRandomBigInt } from "../src/util";
import { sha3_256 } from "@noble/hashes/sha3";
import { Point } from "../src/types";
import { Dealer, ReconstructSecret, VerifyDecryptedShare, verifyDistributionShares } from "../src/participant";

test('participant::PVSS', () => {
  const threshold = 3;
  const n = 4;
  const participants: Dealer[] = [];
  const dealer = new Dealer(p256.utils.randomPrivateKey());
  const pks: Uint8Array[] = [];

  // Generate participants
  for (let i = 0; i < n; i++) {
    const priv = p256.utils.randomPrivateKey();
    const participant = new Dealer(priv);
    participants.push(participant);
    pks.push(participant.pk)
  }

  let s = BigInt("33011033");
  dealer.distributeSecret(s, pks, threshold)
    .then((secret) => {
      console.log("Distributed secret:", secret)
      expect(n).toEqual(secret.Shares.length)
      expect(secret.U).not.toEqual(0n)
      expect(secret.Commitments.length).toEqual(threshold)
      const isVerified = verifyDistributionShares(secret);
      expect(isVerified).toBeTruthy();

      const decShares = [];
      for (var i = 0; i < participants.length; i++) {
        const decShare = participants.at(i).extractSecretShare(secret);
        expect(decShare).not.toBeNull();
        console.log(decShare);
        decShares.push(decShare);
      }

      for (var i = 0; i < decShares.length; i++) {
        const ok = VerifyDecryptedShare(decShares[i]);
        expect(ok).toBeTruthy();
      }

      const sReconstructed = ReconstructSecret([decShares[0], decShares[1], decShares[3]], secret.U)
      expect(sReconstructed).not.toBeNull();
      expect(sReconstructed).toEqual(s)
    })
});
