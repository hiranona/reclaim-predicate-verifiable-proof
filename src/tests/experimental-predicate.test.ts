import assert from 'node:assert'
import { createHash } from 'node:crypto'
import { describe, it } from 'node:test'
import { hexlify } from 'ethers'

import {
	assertExperimentalPredicateProof,
	type ExperimentalPredicateProof
} from '#src/providers/http/experimental-predicate.ts'
import {
	buildExperimentalPredicateProofPackage,
	type ExperimentalPredicateProofPackage,
	verifyExperimentalPredicateProofPackage
} from '#src/providers/http/experimental-predicate-package.ts'
import { makeProfileAgeGte20ToyVerifier } from '#src/providers/http/experimental-predicate-verifier.ts'
import {
	ServiceSignatureType,
	TranscriptMessageSenderType,
	type ProviderClaimData
} from '#src/proto/api.ts'
import { providers } from '#src/providers/index.ts'
import { CURRENT_ATTESTOR_VERSION } from '#src/config/index.ts'
import { assertValidProviderTranscript } from '#src/server/utils/assert-valid-claim-request.ts'
import {
	canonicalStringify,
	createSignDataForClaim,
	getIdentifierFromClaimInfo,
	logger,
	strToUint8Array
} from '#src/utils/index.ts'
import { SIGNATURES } from '#src/utils/signatures/index.ts'

const BASE_PROOF: ExperimentalPredicateProof = {
	version: 'tlsn-mpc-lab.profile-age-predicate.v1',
	providerTemplateHash: 'template-hash',
	responseSelector: '$.age',
	predicate: {
		kind: 'age_gte',
		threshold: 20,
	},
	publicInput: {
		providerTemplateHash: 'template-hash',
		responseSelector: '$.age',
		hiddenValueBinding: 'toprf-nullifier',
		circuitHash: '',
		predicateResult: true,
	},
	proof: {
		system: 'toy',
		payload: {},
	},
}

describe('experimental predicate proof binding', () => {
	it('accepts a proof bound to a verified TOPRF hidden value', async() => {
		const proof = withCircuitHash(BASE_PROOF)
		let verifierCalled = false

		await assertExperimentalPredicateProof(
			params(),
			{
				version: 0 as any,
				claimContext: { experimentalPredicateProof: proof },
				hiddenValueBindings: [binding('toprf-nullifier')],
				experimentalPredicateProofVerifier: received => {
					verifierCalled = true
					assert.equal(received, proof)
					return true
				},
			}
		)

		assert.equal(verifierCalled, true)
	})

	it('rejects a predicate proof without a matching TOPRF hidden value binding', async() => {
		const proof = withCircuitHash(BASE_PROOF)

		await assert.rejects(
			() => assertExperimentalPredicateProof(
				params(),
				{
					version: 0 as any,
					claimContext: { experimentalPredicateProof: proof },
					hiddenValueBindings: [binding('other-nullifier')],
					experimentalPredicateProofVerifier: () => true,
				}
			),
			/hidden witness is not bound/
		)
	})

	it('rejects a predicate proof when no verifier is configured', async() => {
		const proof = withCircuitHash(BASE_PROOF)

		await assert.rejects(
			() => assertExperimentalPredicateProof(
				params(),
				{
					version: 0 as any,
					claimContext: { experimentalPredicateProof: proof },
					hiddenValueBindings: [binding('toprf-nullifier')],
				}
			),
			/No experimental predicate proof verifier configured/
		)
	})

	it('rejects selector mismatch against the provider redaction template', async() => {
		const proof = withCircuitHash({
			...BASE_PROOF,
			responseSelector: '$.height',
			publicInput: {
				...BASE_PROOF.publicInput,
				responseSelector: '$.height',
			},
		})

		await assert.rejects(
			() => assertExperimentalPredicateProof(
				params(),
				{
					version: 0 as any,
					claimContext: { experimentalPredicateProof: proof },
					hiddenValueBindings: [binding('toprf-nullifier')],
					experimentalPredicateProofVerifier: () => true,
				}
			),
			/selector mismatch/
		)
	})

	it('verifies the experimental profile age verifier adapter', () => {
		const proof = withCircuitHash(BASE_PROOF)
		const verifier = makeProfileAgeGte20ToyVerifier('template-hash', '$.age')

		assert.equal(verifier.circuitHash, proof.publicInput.circuitHash)
		assert.equal(verifier.verify(proof), true)
		assert.equal(
			verifier.verify({
				...proof,
				publicInput: {
					...proof.publicInput,
					predicateResult: false,
				},
			}),
			false
		)
	})

	it('runs through the HTTP provider receipt validation hook', async() => {
		const proof = withCircuitHash(BASE_PROOF)
		let verifierCalled = false

		await providers.http.assertValidProviderReceipt({
			receipt: httpReceipt(),
			clientVersion: CURRENT_ATTESTOR_VERSION,
			params: params(),
			logger,
			ctx: {
				version: CURRENT_ATTESTOR_VERSION,
				claimContext: { experimentalPredicateProof: proof },
				hiddenValueBindings: [binding('toprf-nullifier')],
				experimentalPredicateProofVerifier: received => {
					verifierCalled = true
					assert.equal(received, proof)
					return true
				},
			},
		})

		assert.equal(verifierCalled, true)
	})

	it('rejects through the HTTP provider hook when the predicate proof is unbound', async() => {
		const proof = withCircuitHash(BASE_PROOF)

		await assert.rejects(
			() => providers.http.assertValidProviderReceipt({
				receipt: httpReceipt(),
				clientVersion: CURRENT_ATTESTOR_VERSION,
				params: params(),
				logger,
				ctx: {
					version: CURRENT_ATTESTOR_VERSION,
					claimContext: { experimentalPredicateProof: proof },
					hiddenValueBindings: [binding('other-nullifier')],
					experimentalPredicateProofVerifier: () => true,
				},
			}),
			/hidden witness is not bound/
		)
	})

	it('passes predicate context through server-side provider transcript validation', async() => {
		const proof = withCircuitHash(BASE_PROOF)
		let verifierCalled = false
		const info = {
			provider: 'http',
			parameters: JSON.stringify(params()),
			context: JSON.stringify({ experimentalPredicateProof: proof }),
		}

		const updatedInfo = await assertValidProviderTranscript(
			httpReceipt(),
			{ clientVersion: CURRENT_ATTESTOR_VERSION } as any,
			info as any,
			logger,
			{
				version: CURRENT_ATTESTOR_VERSION,
				hiddenValueBindings: [binding('toprf-nullifier')],
				experimentalPredicateProofVerifier: received => {
					verifierCalled = true
					assert.deepEqual(received, proof)
					return true
				},
			} as any
		)

		assert.equal(verifierCalled, true)
		const updatedContext = JSON.parse(updatedInfo.context)
		assert.equal(updatedContext.experimentalPredicateProof, undefined)
		assert.deepEqual(updatedContext.hiddenPredicate, {
			version: 'tlsn-mpc-lab.hidden-predicate-statement.v1',
			templateHash: proof.providerTemplateHash,
			responseSelector: proof.responseSelector,
			selectedField: {
				selector: proof.responseSelector,
				bindingKind: 'toprf-json-redaction',
				boundSegmentEncoding: 'json-key-value-segment',
			},
			hiddenValueBindingHash: '2b954e7c5c9841c58136066ee81261ecfec31beeae98016653c777ed85896c5a',
			transcriptBinding: {
				kind: 'toprf',
				recordNumber: 1,
				packetOffset: 10,
				length: 2,
				nullifierHash: '2b954e7c5c9841c58136066ee81261ecfec31beeae98016653c777ed85896c5a',
			},
			predicate: proof.predicate,
			predicateResult: true,
			proofSystem: proof.proof.system,
			proofHash: '158db608811ec272ae0dd26b5b9b76cd1763cab8e22faddb9479bd400d2199a5',
		})
		assert.equal(typeof updatedContext.providerHash, 'string')
	})

	it('verifies a signed third-party predicate proof package skeleton', async() => {
		const proof = withCircuitHash(BASE_PROOF)
		const claim = claimWithHiddenPredicate({
			hiddenPredicate: hiddenPredicateForProof(proof),
		})
		const pkg = buildExperimentalPredicateProofPackage(
			claim,
			proof.proof,
			await signClaimAsTestAttestor(claim),
			[fakeToprfTranscriptMessage()]
		)

		const result = await verifyExperimentalPredicateProofPackage(pkg)
		assert.equal(result.ok, true, result.errors.join('; '))
		assert.equal(result.hiddenPredicate?.responseSelector, '$.age')
		assert.equal(
			pkg.reveal.attestorObservedTranscriptCommitment.responseSelector,
			'$.age'
		)
		assert.equal(
			typeof pkg.reveal.attestorObservedTranscriptCommitment.commitmentHash,
			'string'
		)
		assert.equal(pkg.warning.independentThirdPartyVerification, true)
		assert.deepEqual(pkg.warning.missing, [])
		assert.equal(
			pkg.reveal.replayableRevealProof?.records[0].packetOffset,
			10
		)
		assert.equal(result.limitations.length, 2)
	})

	it('rejects a third-party predicate package with a detached proof', async() => {
		const proof = withCircuitHash(BASE_PROOF)
		const claim = claimWithHiddenPredicate({
			hiddenPredicate: {
				...hiddenPredicateForProof(proof),
				proofHash: 'not-the-proof-hash',
			},
		})
		const pkg = buildExperimentalPredicateProofPackage(
			claim,
			proof.proof,
			await signClaimAsTestAttestor(claim),
			[fakeToprfTranscriptMessage()]
		)

		const result = await verifyExperimentalPredicateProofPackage(pkg)
		assert.equal(result.ok, false)
		assert.match(result.errors.join('; '), /proof hash/)
	})

	it('rejects a third-party predicate package with a detached transcript commitment', async() => {
		const proof = withCircuitHash(BASE_PROOF)
		const claim = claimWithHiddenPredicate({
			hiddenPredicate: hiddenPredicateForProof(proof),
		})
		const pkg = buildExperimentalPredicateProofPackage(
			claim,
			proof.proof,
			await signClaimAsTestAttestor(claim),
			[fakeToprfTranscriptMessage()]
		)

		pkg.reveal.attestorObservedTranscriptCommitment.transcriptBinding = {
			...pkg.reveal.attestorObservedTranscriptCommitment.transcriptBinding,
			packetOffset: 11,
		}

		const result = await verifyExperimentalPredicateProofPackage(pkg)
		assert.equal(result.ok, false)
		assert.match(result.errors.join('; '), /transcript commitment/)
	})

	it('rejects a third-party predicate package with a mismatched nullifier hash', async() => {
		const proof = withCircuitHash(BASE_PROOF)
		const claim = claimWithHiddenPredicate({
			hiddenPredicate: {
				...hiddenPredicateForProof(proof),
				transcriptBinding: {
					...hiddenPredicateForProof(proof).transcriptBinding,
					nullifierHash: 'bad-hash',
				},
			},
		})
		const pkg = buildExperimentalPredicateProofPackage(
			claim,
			proof.proof,
			await signClaimAsTestAttestor(claim),
			[fakeToprfTranscriptMessage()]
		)

		const result = await verifyExperimentalPredicateProofPackage(pkg)
		assert.equal(result.ok, false)
		assert.match(result.errors.join('; '), /nullifier hash/)
	})

	it('rejects a third-party predicate package with a detached replayable reveal proof', async() => {
		const proof = withCircuitHash(BASE_PROOF)
		const claim = claimWithHiddenPredicate({
			hiddenPredicate: hiddenPredicateForProof(proof),
		})
		const pkg = buildExperimentalPredicateProofPackage(
			claim,
			proof.proof,
			await signClaimAsTestAttestor(claim),
			[fakeToprfTranscriptMessage()]
		)

		pkg.reveal.replayableRevealProof!.records[0].packetOffset = 11

		const result = await verifyExperimentalPredicateProofPackage(pkg)
		assert.equal(result.ok, false)
		assert.match(result.errors.join('; '), /replayable reveal proof/)
	})

	it('rejects a third-party predicate package without attestor claim signature', async() => {
		const proof = withCircuitHash(BASE_PROOF)
		const pkg = buildExperimentalPredicateProofPackage(
			claimWithHiddenPredicate({
				hiddenPredicate: {
					...hiddenPredicateForProof(proof),
				},
			}),
			proof.proof
		)

		const result = await verifyExperimentalPredicateProofPackage(pkg)
		assert.equal(result.ok, false)
		assert.match(result.errors.join('; '), /attestor claim signature/)
	})
})

function params() {
	return {
		url: 'https://xargs.org/',
		method: 'GET',
		responseMatches: [
			{ type: 'contains', value: 'HTTP/1.1 200 OK' },
		],
		responseRedactions: [
			{ jsonPath: '$.age', hash: 'oprf' },
		],
	} as any
}

function binding(nullifierText: string) {
	return {
		kind: 'toprf' as const,
		nullifierText,
		length: 2,
		recordNumber: 1,
		packetOffset: 10,
	}
}

function hiddenPredicateForProof(proof: ExperimentalPredicateProof) {
	return {
		version: 'tlsn-mpc-lab.hidden-predicate-statement.v1',
		templateHash: proof.providerTemplateHash,
		responseSelector: proof.responseSelector,
		selectedField: {
			selector: proof.responseSelector,
			bindingKind: 'toprf-json-redaction',
			boundSegmentEncoding: 'json-key-value-segment',
		},
		hiddenValueBindingHash: '2b954e7c5c9841c58136066ee81261ecfec31beeae98016653c777ed85896c5a',
		transcriptBinding: {
			kind: 'toprf',
			recordNumber: 1,
			packetOffset: 10,
			length: 2,
			nullifierHash: '2b954e7c5c9841c58136066ee81261ecfec31beeae98016653c777ed85896c5a',
		},
		predicate: proof.predicate,
		predicateResult: true,
		proofSystem: proof.proof.system,
		proofHash: '158db608811ec272ae0dd26b5b9b76cd1763cab8e22faddb9479bd400d2199a5',
	}
}

function fakeToprfTranscriptMessage() {
	return {
		sender: TranscriptMessageSenderType.TRANSCRIPT_MESSAGE_SENDER_TYPE_SERVER,
		message: new Uint8Array([1, 2, 3]),
		reveal: {
			zkReveal: {
				proofs: [],
				toprfs: [
					{
						startIdx: 8,
						proofData: new Uint8Array([7]),
						payload: {
							nullifier: new Uint8Array([1, 2]),
							responses: [],
							dataLocation: {
								fromIndex: 2,
								length: 2,
							},
						},
					},
				],
				oprfRawMarkers: [],
				overshotOprfRawLength: 0,
			},
		},
	}
}

function withCircuitHash(proof: ExperimentalPredicateProof): ExperimentalPredicateProof {
	return {
		...proof,
		publicInput: {
			...proof.publicInput,
			circuitHash: createHash('sha256')
				.update(JSON.stringify({
					version: proof.version,
					providerTemplateHash: proof.providerTemplateHash,
					responseSelector: proof.responseSelector,
					predicate: proof.predicate,
				}))
				.digest('hex'),
		},
	}
}

function claimWithHiddenPredicate(
	context: Record<string, unknown>
): ExperimentalPredicateProofPackage['claim'] {
	const claim = {
		provider: 'http',
		parameters: '{}',
		context: canonicalStringify(context),
		identifier: '',
		owner: '0x0000000000000000000000000000000000000001',
		timestampS: 1,
		epoch: 1,
	} satisfies ProviderClaimData
	claim.identifier = getIdentifierFromClaimInfo({ ...claim })
	return claim
}

async function signClaimAsTestAttestor(
	claim: ExperimentalPredicateProofPackage['claim']
): Promise<ExperimentalPredicateProofPackage['attestation']> {
	const signatureType = ServiceSignatureType.SERVICE_SIGNATURE_TYPE_ETH
	const signature = SIGNATURES[signatureType]
	const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
	const publicKey = signature.getPublicKey(privateKey)
	return {
		signatureType,
		attestorAddress: signature.getAddress(publicKey),
		claimSignature: hexlify(
			await signature.sign(
				strToUint8Array(createSignDataForClaim({ ...claim })),
				privateKey
			)
		),
	}
}

function httpReceipt() {
	return [
		{
			sender: 'client' as const,
			message: Buffer.from([
				'GET / HTTP/1.1',
				'Host: xargs.org',
				'Connection: close',
				'Accept-Encoding: identity',
				'',
				'',
			].join('\r\n')),
		},
		{
			sender: 'server' as const,
			message: Buffer.from([
				'HTTP/1.1 200 OK',
				'Content-Length: 0',
				'Connection: close',
				'',
				'',
			].join('\r\n')),
		},
	]
}
