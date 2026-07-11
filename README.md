# Reclaim Predicate Verifiable Proof

This fork is an experimental extension of Reclaim Attestor Core for hidden
predicate proofs with third-party verification metadata.

The upstream README is preserved as [README-upstream.md](./README-upstream.md).
Japanese documentation is available in [README-ja.md](./README-ja.md).

## What This Branch Adds

This branch adds an experimental flow where a client can prove a predicate about
a hidden HTTP response field without signing the raw hidden field into the claim
context.

New capabilities:

- Bind an experimental predicate proof to a TOPRF-backed hidden response value.
- Convert the client-supplied `experimentalPredicateProof` into a signed
  `hiddenPredicate` statement in the claim context.
- Store only `hiddenValueBindingHash` in the signed statement, not the raw
  TOPRF nullifier text.
- Add a verifier registry keyed by predicate circuit hash.
- Add an experimental profile-age verifier adapter.
- Build a signed third-party proof package from a Reclaim claim response.
- Include an attestor-observed transcript commitment derived from the signed
  `hiddenPredicate.transcriptBinding`.
- Optionally include replayable ZK/TOPRF reveal metadata copied from the
  original `ClaimTunnelRequest.transcript`.
- Verify package integrity, attestor claim signature, predicate proof binding,
  transcript binding, and replayable reveal proof binding.

The implementation is intentionally experimental. The included verifier adapter
is a toy adapter for the profile age predicate shape. A production version needs
a real circuit verifier and verifier artifacts.

## Main Files

- `src/providers/http/experimental-predicate.ts`
  - validates and binds predicate proofs during HTTP provider verification.
- `src/providers/http/experimental-predicate-package.ts`
  - builds and verifies third-party proof packages.
- `src/providers/http/experimental-predicate-verifier.ts`
  - contains the experimental verifier adapter shape.
- `src/utils/zk.ts`
  - records TOPRF hidden value bindings during ZK reveal verification.
- `src/server/utils/assert-valid-claim-request.ts`
  - moves verified predicate statements into the signed claim context.
- `src/client/create-claim.ts`
  - exposes `onClaimRequestPrepared` so callers can retain the transcript needed
    to build replayable third-party packages.

## Flow

```text
Client
  |
  | 1. Fetch HTTPS response through Reclaim attestor
  | 2. Select JSON field with responseRedactions[... hash: "oprf"]
  | 3. Generate TOPRF/ZK reveal for the hidden response segment
  | 4. Attach experimentalPredicateProof in claim context
  v
Attestor
  |
  | 5. verifyZkPacket(...)
  |      - verifies ZK/TOPRF reveal
  |      - records HiddenValueBinding
  |
  | 6. assertExperimentalPredicateProof(...)
  |      - checks selector/template/circuit/predicate result
  |      - checks proof public input binds to HiddenValueBinding
  |      - calls registered predicate verifier
  |
  | 7. assertValidProviderTranscript(...)
  |      - deletes experimentalPredicateProof
  |      - writes hiddenPredicate into signed claim context
  |
  | 8. claimTunnel(...)
  |      - signs createSignDataForClaim(claim)
  v
Signed Reclaim Claim
  |
  | 9. buildExperimentalPredicateProofPackageFromClaimResponse(...)
  |      - adds attestor signature material
  |      - adds transcript commitment
  |      - optionally copies replayable zkReveal/TOPRF metadata
  v
Third Party
  |
  | 10. verifyExperimentalPredicateProofPackage(...)
  |       - verifies claim signature
  |       - recomputes claim identifier and signing payload hash
  |       - checks hiddenPredicate/proof hash
  |       - checks transcript commitment
  |       - checks replayable reveal proof binding
  v
Accept / Reject
```

## Tamper Detection Matrix

| Tampering attempt | Detected by | Function / file |
| --- | --- | --- |
| Change the response selector in the predicate proof | Selector check against first OPRF JSON redaction | `assertExperimentalPredicateProof` in `src/providers/http/experimental-predicate.ts` |
| Use a proof whose public input selector differs from the proof selector | Public input selector check | `assertExperimentalPredicateProof` |
| Use a proof for another provider template | Public input template hash check | `assertExperimentalPredicateProof` |
| Swap the circuit hash | Circuit hash recomputation | `assertExperimentalPredicateProof` |
| Claim an unsupported or false predicate | Predicate kind, threshold, and result checks | `assertExperimentalPredicateProof` |
| Bind the predicate proof to a value not proven by TOPRF/ZK | Hidden value binding lookup | `assertExperimentalPredicateProof` |
| Omit the predicate verifier | Verifier presence check | `assertExperimentalPredicateProof` |
| Fail the predicate verifier | Registered verifier result check | `assertExperimentalPredicateProof`; registry in `src/config/index.ts` |
| Leak raw hidden nullifier in signed context | Signed statement stores `hiddenValueBindingHash` only | `buildHiddenPredicateStatement` in `experimental-predicate.ts` |
| Reattach the detached predicate proof to another signed claim | `proofHash` check against signed `hiddenPredicate` | `verifyExperimentalPredicateProofPackage` in `experimental-predicate-package.ts` |
| Modify provider, parameters, context, owner, timestamp, or epoch after signing | Attestor claim signature check | `verifyClaimSignature` in `experimental-predicate-package.ts` |
| Modify provider, parameters, or context while keeping stale identifier | Identifier recomputation | `computeClaimIdentifier` in `experimental-predicate-package.ts` |
| Modify the claim signing payload description | Signing payload hash check | `buildClaimSigningPayload` and `verifyExperimentalPredicateProofPackage` |
| Modify transcript record number, packet offset, length, or nullifier hash in the package commitment | Commitment recomputation | `buildAttestorObservedTranscriptCommitment` and `verifyExperimentalPredicateProofPackage` |
| Make `hiddenValueBindingHash` inconsistent with the transcript binding nullifier hash | Hash equality check | `verifyExperimentalPredicateProofPackage` |
| Omit replayable reveal metadata but claim independent third-party verification | Warning consistency check | `verifyReplayableRevealProof` in `experimental-predicate-package.ts` |
| Attach replayable reveal metadata from another range | Transcript range binding check | `verifyReplayableRevealProof` |
| Modify replayable reveal metadata after package creation | Replay proof hash check | `verifyReplayableRevealProof` |
| Use a toy proof with the wrong predicate result or shape | Verifier adapter check | `verifyProfileAgeGte20ToyProof` in `experimental-predicate-verifier.ts` |

## Current Limitations

- The predicate verifier adapter is experimental and toy-only.
- The third-party package verifier checks replayable reveal metadata binding, but
  does not itself rerun the full ZK verifier. A caller that wants full replay
  should feed the bundled `zkReveal` and original TLS record material into
  Reclaim's existing `verifyZkPacket(...)` path.
- `replayableRevealProof` is available only if the caller captures the original
  `ClaimTunnelRequest.transcript` via `onClaimRequestPrepared`.
- This branch is not a production API. It is a proof-of-concept for evaluating
  whether Reclaim's existing TOPRF/ZK machinery can support hidden predicate
  statements plus third-party package verification.

## Tests

Targeted tests used while developing this branch:

```bash
npm run run:test-files -- --test src/tests/experimental-predicate.test.ts
npm run run:test-files -- --test-name-pattern "experimental predicate" --test src/tests/claim-creation.test.ts
npm run run:test-files -- --test src/tests/http-provider-utils.test.ts
```

