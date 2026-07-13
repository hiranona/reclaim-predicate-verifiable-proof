# Reclaim Predicate Verifiable Proof

This fork is an experimental extension of Reclaim Attestor Core for hidden
predicate proofs with third-party verification metadata.

> This fork treats `main` as the stable baseline for this experiment, not as a
> clean mirror of upstream `reclaimprotocol/attestor-core`.

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

## Usage: Role-Based Demo

This demo shows the protocol shape by separating the origin HTTPS server,
Reclaim proxy/attestor, client/prover, and third-party verifier into terminal
commands.

The example statement is:

```text
The JSON field $.age from https://localhost:9443/profile satisfies age >= 20.
The raw age value is hidden from the signed claim context.
```

The demo response body is:

```json
{"name":"alice","age":25,"height":170}
```

The predicate verifier is a toy adapter. It demonstrates the binding points for
a real range-proof verifier, circuit hash, verifying key, and registry entry,
but it is not a production range-proof implementation.

Run all commands in this section from this repository root:

```bash
cd reclaim-predicate-verifiable-proof
```

### Environment

This fork uses Node's built-in TypeScript stripping in the demo and test
scripts, so use Node 22 or newer. Node 18 is not sufficient because it does not
support the required `node --experimental-strip-types`,
`--experimental-test-module-mocks`, and `--test-force-exit` flags.

Verified environment for this branch:

| Component | Version |
| --- | --- |
| OS | Ubuntu 24.04.4 LTS on WSL2 |
| Kernel | Linux 5.15.167.4-microsoft-standard-WSL2 x86_64 |
| Node.js | v22.23.1 |
| npm | 9.2.0 |

If you switch Node versions after installing dependencies, rebuild native
modules before running tests:

```bash
npm rebuild re2
```

### Install Dependencies

```bash
npm ci
```

Use `NODE_ENV=test` for the commands below so the local demo keys in `.env.test`
are loaded.

### Demo Challenges

The demo includes two verifier challenges. They intentionally use different
JSON selectors, predicates, template hashes, and circuit hashes so the flow is
not tied to a single hard-coded statement.

| Demo | Fixture body | Selector | Predicate | Package |
| --- | --- | --- | --- | --- |
| Demo 1: Alice age proof | `{"name":"alice","age":25,"height":170}` | `$.age` | `age >= 20` | `predicate-package.json` |
| Demo 2: Bob income proof | `{"name":"bob","annualIncome":85000,"currency":"USD","employer":"example-corp"}` | `$.annualIncome` | `annualIncome >= 50000 USD` | `predicate-package-income.json` |

In both cases the verifier challenge fixes the provider template, response
selector, predicate schema, proof system, and circuit hash. The client produces
the matching proof, the attestor checks it against the TOPRF/ZK-bound hidden
response segment, and the third-party verifier checks the resulting package
against the same signed challenge identity.

This is the important generalization point: the client is not proving a
repository-wide hard-coded statement. The verifier's "challenge" is represented
in this demo by a `DemoChallenge` entry in
`src/scripts/experimental-predicate-demo-utils.ts`. Each challenge defines the
same fields that a production predicate registry entry would eventually carry:

```ts
{
  templateHash,
  responseSelector,
  predicate,
  proofSystem,
  circuitHash
}
```

Demo 1 and Demo 2 therefore exercise the same Reclaim/TOPRF/package plumbing
with different verifier-defined statements:

```text
Alice challenge -> $.age          -> age_gte(20)              -> circuitHash A
Bob challenge   -> $.annualIncome -> income_gte(50000, "USD") -> circuitHash B
```

The attestor registers both challenge verifiers at startup. The client selects
one with `--demo age` or `--demo income`, builds the matching proof, and the
third-party verifier checks the signed package against the challenge identity
embedded in `hiddenPredicate`.

### Role Map

| Role | Command | Data boundary |
| --- | --- | --- |
| Origin HTTPS server | `npm run demo:predicate:fixture` | Serves the selected demo JSON at `/profile` or `/income`. |
| Proxy / Attestor | `npm run demo:predicate:attestor` | Verifies the Reclaim transcript, TOPRF/ZK reveal, hidden-value binding, and registered predicate proof before signing the claim. |
| Client fetch step | `npm run demo:predicate:fetch` | Reads the selected origin JSON and writes the client-observed input file. |
| Client / Prover | `npm run demo:predicate:client` | Reads the client-observed input file, fetches through the attestor, proves the selected hidden predicate, and writes a third-party package JSON file. |
| Third-party verifier | `npm run demo:predicate:verify` | Reads the package JSON and verifies the attestor signature, claim binding, predicate proof hash, transcript binding, and replayable reveal binding. |

### Demo 1: Alice Age Proof

Demo 1 is the default. All commands below can omit `--demo age`; it is shown
explicitly to make the verifier challenge visible.

#### 1. Origin HTTPS Server

Terminal 1:

```bash
NODE_ENV=test npm run demo:predicate:fixture -- \
  --demo age \
  --host localhost \
  --port 9443
```

This starts a local HTTPS fixture at:

```text
https://localhost:9443/profile
```

The selected field is `$.age`. The intended predicate is `age >= 20`.

#### 2. Proxy / Attestor

Terminal 2:

```bash
NODE_ENV=test npm run demo:predicate:attestor -- \
  --host 127.0.0.1 \
  --port 8001 \
  --out-dir artifacts/experimental-predicate-demo/attestor
```

This starts a local Reclaim attestor at:

```text
ws://127.0.0.1:8001/ws
```

At startup it registers the demo predicate verifier for:

```text
template: experimental-predicate-demo-profile-v1
selector: $.age
predicate: age >= 20
proof system: toy
```

It also registers the Bob income verifier used by Demo 2:

```text
template: experimental-predicate-demo-income-v1
selector: $.annualIncome
predicate: annualIncome >= 50000 USD
proof system: toy
```

It also writes attestor-side demo metadata to:

```text
artifacts/experimental-predicate-demo/attestor/attestor-metadata.json
```

In a production design this verifier registration should be replaced by a
shared predicate registry that maps provider template, selector, predicate
schema, circuit hash, and verifier artifact.

#### 3a. Client Fetch Step

Terminal 3:

```bash
NODE_ENV=test npm run demo:predicate:fetch -- \
  --demo age \
  --fixture-url https://localhost:9443/profile \
  --out-file artifacts/experimental-predicate-demo/client/client-observed-profile.json
```

This is the client-side "curl-like" step. It writes the profile body that the
client will use as predicate witness input:

```text
artifacts/experimental-predicate-demo/client/client-observed-profile.json
```

This step is included only to make plaintext tamper checks easy to inspect in
the demo. It is not the trust root of the Reclaim claim, and a production client
would normally derive the witness input during the attestor-mediated fetch in
3b instead of doing this separate curl-like fetch.

For tamper checks, edit this file before running 3b. For example, changing
`"age": 25` to `"age": 15` makes proof generation fail locally. Changing it to
another value such as `99` makes the later attestor binding fail because the
predicate proof no longer matches the TOPRF hidden value observed through the
Reclaim transcript.

#### 3b. Client / Prover

Terminal 3:

```bash
NODE_ENV=test npm run demo:predicate:client -- \
  --demo age \
  --fixture-url https://localhost:9443/profile \
  --attestor-url ws://127.0.0.1:8001/ws \
  --profile-file artifacts/experimental-predicate-demo/client/client-observed-profile.json \
  --out-dir artifacts/experimental-predicate-demo/client
```

The client/prover does the following:

- reads `client-observed-profile.json` and builds the toy `age >= 20`
  predicate proof input;
- fetches the fixture URL through the Reclaim attestor;
- marks `$.age` as `responseRedactions: [{ jsonPath: "$.age", hash: "oprf" }]`;
- attaches `experimentalPredicateProof` to the claim context;
- captures the prepared `ClaimTunnelRequest.transcript`;
- receives the signed Reclaim claim from the attestor;
- writes a third-party package to:

```text
artifacts/experimental-predicate-demo/client/predicate-package.json
```

This command is run by the client/prover, but the accept/reject decision is made
by the proxy/attestor during claim verification.

The signed claim context contains `hiddenPredicate`. It does not contain the raw
hidden age value.

#### 4. Third-Party Verifier

Terminal 4:

```bash
NODE_ENV=test npm run demo:predicate:verify -- \
  --package artifacts/experimental-predicate-demo/client/predicate-package.json
```

The verifier reads only the package file and checks:

- attestor claim signature;
- attestor result signature over the stripped request, including fixed IVs;
- recomputed claim identifier and signing payload hash;
- signed `hiddenPredicate.proofHash` against the detached predicate proof;
- transcript commitment derived from `hiddenPredicate.transcriptBinding`;
- ciphertext hash against the signed `hiddenPredicate.transcriptBinding`;
- replayable reveal proof range binding;
- replayed Reclaim ZK/TOPRF verification for the signed hidden transcript range;
- warning metadata for missing independent-verification material.

The verifier does not learn the raw hidden age value from the signed claim
context.

In the role-based demo path, the package includes the hidden TLS record
ciphertext, the replayable `zkReveal`, and the attestor result signature over
the stripped request that contains the fixed IVs. The signed claim context
contains the ciphertext hash and cipher suite. This lets the third-party
verifier detect client-side ciphertext / hidden-witness substitution by
checking the signed ciphertext hash and rerunning `verifyZkPacket(...)`.

### Demo 2: Bob Income Proof

Demo 2 uses the same roles and attestor process, but a different verifier
challenge:

```text
The JSON field $.annualIncome from https://localhost:9443/income satisfies
annualIncome >= 50000 USD. The raw income value is hidden from the signed claim
context.
```

Start a Bob income fixture:

```bash
NODE_ENV=test npm run demo:predicate:fixture -- \
  --demo income \
  --host localhost \
  --port 9443
```

If the attestor from Demo 1 is still running, reuse it. It registers both demo
verifiers at startup. Then fetch the fixture body:

```bash
NODE_ENV=test npm run demo:predicate:fetch -- \
  --demo income \
  --fixture-url https://localhost:9443/income \
  --out-file artifacts/experimental-predicate-demo/client/client-observed-income.json
```

Run the client/prover:

```bash
NODE_ENV=test npm run demo:predicate:client -- \
  --demo income \
  --fixture-url https://localhost:9443/income \
  --attestor-url ws://127.0.0.1:8001/ws \
  --profile-file artifacts/experimental-predicate-demo/client/client-observed-income.json \
  --package-file artifacts/experimental-predicate-demo/client/predicate-package-income.json \
  --out-dir artifacts/experimental-predicate-demo/client
```

Verify the Bob package:

```bash
NODE_ENV=test npm run demo:predicate:verify -- \
  --package artifacts/experimental-predicate-demo/client/predicate-package-income.json
```

For tamper checks, edit `client-observed-income.json` before running the
client/prover. Changing `annualIncome` to `40000` fails local proof generation.
Changing it to another satisfying value, such as `90000`, fails later because
the predicate proof no longer matches the TOPRF hidden value observed through
the Reclaim transcript.

### Adding Another Predicate Demo

To add another demo, define a new verifier challenge and wire it through the
same four roles:

1. Define the challenge/template in
   `src/scripts/experimental-predicate-demo-utils.ts`: template id, endpoint,
   response selector, predicate kind and parameters, proof system, and circuit
   hash derivation.
2. Add or select a fixture response with a stable JSON shape and a hidden field
   path that can be bound by TOPRF/ZK redaction.
3. Implement the client proof builder for that challenge: parse the response,
   extract the hidden witness, construct public input, and bind it to
   `hiddenValueBinding`.
4. Register an attestor verifier in
   `src/scripts/experimental-predicate-demo-attestor.ts`, keyed by the circuit
   hash.
5. Ensure the third-party package includes the signed `hiddenPredicate`,
   detached predicate proof, transcript binding, ciphertext hash, and replayable
   reveal metadata if independent verification is required.
6. Add tamper checks for wrong selector, wrong template, false predicate, stale
   proof attached to another claim, and changed ciphertext/reveal range.

In a production system this challenge object should become a shared predicate
registry entry. The client, attestor, and third-party verifier should resolve
the same registry entry instead of trusting client-supplied verifier metadata.

The current demo code is intentionally arranged so most new examples follow the
same edit path:

| Step | File | What to add |
| --- | --- | --- |
| Define the challenge | `src/scripts/experimental-predicate-demo-utils.ts` | Extend `DemoName` and add a new `DEMO_CHALLENGES.<name>` entry with endpoint, fixture body, selector, predicate, template hash, and proof payload label. |
| Accept the predicate shape | `src/providers/http/experimental-predicate.ts` | Add the predicate variant to `ExperimentalPredicate` and allow its basic public-input shape in `isSupportedTruePredicateClaim(...)`. |
| Verify the toy proof | `src/providers/http/experimental-predicate-verifier.ts` | Reuse `makeDemoChallengeToyVerifier(...)` if equality against the challenge is enough, or add a specialized adapter for a richer toy proof. |
| Register the verifier | `src/scripts/experimental-predicate-demo-attestor.ts` | No change is needed for normal demos; it registers all `DEMO_CHALLENGES` entries. |
| Fetch/prove/verify | demo scripts | No change is needed if the new challenge follows the existing JSON numeric-field shape and can be selected by `--demo <name>`. |
| Document the flow | `README.md` | Add the new fixture body, selector, predicate, package path, and tamper examples. |

For example, a future "Carol account balance" demo should not need a new
attestor or verifier command. It should add a challenge like:

```ts
balance: {
  endpoint: "/balance",
  templateHash: "experimental-predicate-demo-balance-v1",
  responseSelector: "$.balance",
  predicate: { kind: "balance_gte", threshold: 1000, currency: "USD" },
  defaultBody: { name: "carol", balance: 1500, currency: "USD" },
  selectedValueKey: "balance"
}
```

Then the same command shape should apply:

```bash
NODE_ENV=test npm run demo:predicate:fixture -- --demo balance
NODE_ENV=test npm run demo:predicate:fetch -- --demo balance
NODE_ENV=test npm run demo:predicate:client -- --demo balance
NODE_ENV=test npm run demo:predicate:verify -- --package artifacts/experimental-predicate-demo/client/predicate-package-balance.json
```

If the new predicate needs a real parser circuit or a different proof system,
the `DemoChallenge` entry is still the right place to record the verifier's
challenge identity. The implementation behind `buildDemoPredicateProof...` and
the registered verifier adapter should then be replaced with the real proof
builder and verifier artifact lookup.

### Regression Tests

The role-based demo above is the user-facing path. The lower-level regression
tests remain useful while editing the fork:

```bash
npm run run:test-files -- --test src/tests/experimental-predicate.test.ts
npm run run:test-files -- --test-name-pattern "experimental predicate" --test src/tests/claim-creation.test.ts
npm run run:test-files -- --test src/tests/http-provider-utils.test.ts
```

## Flow

```text
Client
  |
  | A. Fetch HTTPS response through Reclaim attestor
  | B. Select JSON field with responseRedactions[... hash: "oprf"]
  | C. Generate TOPRF/ZK reveal for the hidden response segment
  | D. Attach experimentalPredicateProof in claim context
  v
Attestor
  |
  | E. verifyZkPacket(...)
  |      - verifies ZK/TOPRF reveal
  |      - records HiddenValueBinding
  |
  | F. assertExperimentalPredicateProof(...)
  |      - checks selector/template/circuit/predicate result
  |      - checks proof public input binds to HiddenValueBinding
  |      - calls registered predicate verifier
  |
  | G. assertValidProviderTranscript(...)
  |      - deletes experimentalPredicateProof
  |      - writes hiddenPredicate into signed claim context
  |
  | H. claimTunnel(...)
  |      - signs createSignDataForClaim(claim)
  v
Signed Reclaim Claim
  |
  | I. buildExperimentalPredicateProofPackageFromClaimResponse(...)
  |      - adds attestor signature material
  |      - adds transcript commitment
  |      - optionally copies replayable zkReveal/TOPRF metadata
  v
Third Party
  |
  | J. verifyExperimentalPredicateProofPackage(...)
  |       - verifies claim signature
  |       - recomputes claim identifier and signing payload hash
  |       - checks hiddenPredicate/proof hash
  |       - checks transcript commitment
  |       - checks replayable reveal proof binding
  |       - checks ciphertext hash binding
  |       - verifies attestor result signature for fixed IVs
  |       - reruns verifyZkPacket(...) for the signed hidden range
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
| Modify the signed request fixed IVs after attestation | Attestor result signature check | `verifyResultSignature` in `experimental-predicate-package.ts` |
| Modify provider, parameters, or context while keeping stale identifier | Identifier recomputation | `computeClaimIdentifier` in `experimental-predicate-package.ts` |
| Modify the claim signing payload description | Signing payload hash check | `buildClaimSigningPayload` and `verifyExperimentalPredicateProofPackage` |
| Modify transcript record number, packet offset, length, or nullifier hash in the package commitment | Commitment recomputation | `buildAttestorObservedTranscriptCommitment` and `verifyExperimentalPredicateProofPackage` |
| Modify the replayed ciphertext for the hidden TLS record | Signed ciphertext hash check, then `verifyZkPacket(...)` replay | `verifyReplayableRevealProof` |
| Make `hiddenValueBindingHash` inconsistent with the transcript binding nullifier hash | Hash equality check | `verifyExperimentalPredicateProofPackage` |
| Omit attestor-observed ciphertext, result signature, or signed request but claim independent third-party verification | Warning consistency check | `verifyReplayableRevealProof` in `experimental-predicate-package.ts` |
| Omit replayable reveal metadata | Warning consistency check | `verifyReplayableRevealProof` |
| Attach replayable reveal metadata from another range | Transcript range binding check | `verifyReplayableRevealProof` |
| Modify replayable reveal metadata after package creation | Replay proof hash check | `verifyReplayableRevealProof` |
| Modify `zkReveal` so it no longer proves the signed hidden transcript binding | Replayed ZK/TOPRF verification | `verifyReplayableZkPacket` in `experimental-predicate-package.ts` |
| Use a toy proof with the wrong predicate result or shape | Verifier adapter check | `verifyProfileAgeGte20ToyProof` in `experimental-predicate-verifier.ts` |

## Current Limitations

- The predicate verifier adapter is experimental and toy-only.
- The role-based demo package includes enough material for the third-party
  verifier to rerun Reclaim ZK/TOPRF verification for the signed hidden range.
  This branch still uses a toy predicate proof and demo OPRF operator. A
  production design should obtain the real verifier artifacts and OPRF/ZK
  operators from a shared registry instead of script-local demo registration.
- `replayableRevealProof` is available only if the caller captures the original
  `ClaimTunnelRequest.transcript` via `onClaimRequestPrepared`.
- This branch is not a production API. It is a proof-of-concept for evaluating
  whether Reclaim's existing TOPRF/ZK machinery can support hidden predicate
  statements plus third-party package verification.

## Path To A Real Predicate Registry

The included `age >= 20` verifier is a toy adapter. It demonstrates where a
predicate verifier plugs into the Reclaim flow, but it is not the right
distribution model for production predicates.

A production design should look closer to the existing
[Explore Providers](https://dev.reclaimprotocol.org/explore) / Reclaim
[Provider](./docs/provider.md) model: a shared registry describes which claim
template, response selector, predicate kind, and circuit artifact belong
together. The client should not invent a private verifier for each claim.
Instead, the client, attestor, and third-party verifier should all resolve the
same registry entry.

That registry entry should include at least:

- provider/template identifier and version;
- response selector and the expected bound segment encoding;
- predicate schema, such as `age_gte` and allowed threshold parameters;
- proof system and circuit hash;
- verifying key or verifier artifact location;
- public input schema and canonicalization rules;
- registry signature, digest, or allowlist metadata so the artifact itself is
  not client-controlled.

In that model the flow becomes:

```text
Claim template / provider definition
  -> registry entry
  -> circuit + verifier artifact
  -> client generates predicate proof
  -> attestor verifies proof through the registry-selected verifier
  -> third party resolves the same registry entry and verifies the package
```

This branch implements the binding and package-verification side of that shape.
It does not yet implement the shared circuit registry or artifact distribution
layer.

## Tests

Targeted tests used while developing this branch:

```bash
npm run run:test-files -- --test src/tests/experimental-predicate.test.ts
npm run run:test-files -- --test-name-pattern "experimental predicate" --test src/tests/claim-creation.test.ts
npm run run:test-files -- --test src/tests/http-provider-utils.test.ts
```

## Build Note

Targeted tests and `npm run build` pass in the verified Node 22 environment
above. If the native `re2` module was installed under another Node version,
rebuild it with `npm rebuild re2` before running the tests.
