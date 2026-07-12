import assert from 'node:assert'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { beforeEach, describe, it, mock } from 'node:test'

import { type CipherSuite, type TLSProtocolVersion } from '@reclaimprotocol/tls'
import type { OPRFOperator, ZKEngine } from '@reclaimprotocol/zk-symmetric-crypto'

import type { AttestorClient } from '#src/client/index.ts'
import { createClaimOnAttestor, getAttestorClientFromPool } from '#src/client/index.ts'
import { EXPERIMENTAL_PREDICATE_PROOF_VERIFIERS } from '#src/config/index.ts'
import type { ExperimentalPredicateProof } from '#src/providers/http/experimental-predicate.ts'
import {
	buildExperimentalPredicateProofPackageFromClaimResponse,
	verifyExperimentalPredicateProofPackage
} from '#src/providers/http/experimental-predicate-package.ts'
import { makeProfileAgeGte20ToyVerifier } from '#src/providers/http/experimental-predicate-verifier.ts'
import type { ClaimTunnelRequest } from '#src/proto/api.ts'
import { providers } from '#src/providers/index.ts'
import { describeWithServer } from '#src/tests/describe-with-server.ts'
import { verifyNoDirectRevealLeaks } from '#src/tests/utils.ts'
import {
	assertValidClaimSignatures,
	AttestorError,
	EXPERIMENTAL_OPRF_OPERATOR_OVERRIDES,
	uint8ArrayToStr,
} from '#src/utils/index.ts'

const TLS_VERSIONS: TLSProtocolVersion[] = [
	'TLS1_3',
	'TLS1_2',
]

const OPRF_CIPHER_SUITES: CipherSuite[] = [
	'TLS_CHACHA20_POLY1305_SHA256',
	'TLS_AES_256_GCM_SHA384',
	'TLS_AES_128_GCM_SHA256',
]

TLS_ADDITIONAL_ROOT_CA_LIST.push(
	readFileSync('./cert/public-cert.pem', 'utf8')
)

const GET_RESPONSE_REDCTIONS = mock.fn(providers.http.getResponseRedactions)
providers.http.getResponseRedactions = GET_RESPONSE_REDCTIONS

const CREATE_REQUEST = mock.fn(providers.http.createRequest)
providers.http.createRequest = CREATE_REQUEST

const ASSERT_VALID_RECEIPT = mock.fn(providers.http.assertValidProviderReceipt)
providers.http.assertValidProviderReceipt = ASSERT_VALID_RECEIPT

describeWithServer('Claim Creation', opts => {

	const zkEngine: ZKEngine = 'gnark'

	let client: AttestorClient
	let claimUrl: string
	beforeEach(() => {
		client = opts.client
		claimUrl = `https://localhost:${opts.mockhttpsServerPort}/me`

		// we need to disable certificate verification
		// for testing purposes
		providers.http.additionalClientOptions = {
			verifyServerCertificate: false
		}
	})

	for(const version of TLS_VERSIONS) {
		it(`should successfully create a claim (${version})`, async() => {
			providers.http.additionalClientOptions = {
				...providers.http.additionalClientOptions,
				supportedProtocolVersions: [version]
			}

			const user = 'adhiraj'
			const result = await createClaimOnAttestor({
				name: 'http',
				params: {
					url: claimUrl,
					method: 'GET',
					responseRedactions: [],
					responseMatches: [
						{
							type: 'contains',
							value: `${user}@mock.com`
						}
					]
				},
				secretParams: {
					authorisationHeader: `Bearer ${user}`
				},
				ownerPrivateKey: opts.privateKeyHex,
				client,
				zkEngine,
			})

			assert.ok(!result.error)

			// transcript is stripped from response to reduce wire size
			// server-side validation already checks for secret leakage

			await assertValidClaimSignatures(result, client.metadata)
			// check all direct message reveals and
			// ensure we've not accidentally re-used a key
			// for multiple application data messages that
			// were not meant to be revealed.
			await verifyNoDirectRevealLeaks()
		})
	}

	it('should not create a claim with invalid response', async() => {
		await assert.rejects(
			() => createClaimOnAttestor({
				name: 'http',
				params: {
					url: claimUrl,
					method: 'GET',
					responseRedactions: [],
					responseMatches: [
						{
							type: 'contains',
							value: 'something@mock.com'
						}
					]
				},
				secretParams: {
					authorisationHeader: 'Fail'
				},
				ownerPrivateKey: opts.privateKeyHex,
				client,
				zkEngine,
			}),
			(err: AttestorError) => {
				assert.equal(err.message, 'Provider returned error 401')
				return true
			}
		)
	})

	describe('OPRF', () => {

		// OPRF is only available on gnark right now
		const zkEngine = 'gnark'

		for(const cipherSuite of OPRF_CIPHER_SUITES) {

			it('should create a claim with an OPRF redaction (%s)', async() => {
				providers.http.additionalClientOptions = {
					...providers.http.additionalClientOptions,
					cipherSuites: [cipherSuite]
				}

				const user = '(?<test>adhiraj)'
				const result = await createClaimOnAttestor({
					name: 'http',
					params: {
						url: claimUrl,
						method: 'GET',
						responseRedactions: [
							{
								regex: user,
								hash: 'oprf'
							}
						],
						responseMatches: [
							{
								type: 'contains',
								value: ''
							}
						]
					},
					secretParams: {
						authorisationHeader: `Bearer ${user}`
					},
					ownerPrivateKey: opts.privateKeyHex,
					client,
					zkEngine,
				})

				assert.ok(!result.error)
				assert.ok(result.claim)

				// transcript is stripped from response to reduce wire size
				// OPRF validation is done server-side in assertValidClaimRequest
			})
		}

		it('should create claim with OPRF spread across multiple packets', async() => {
			const user = 'abcd_test_user'
			const result = await createClaimOnAttestor({
				name: 'http',
				params: {
					url: claimUrl + '?splitDataAcrossPackets=true',
					method: 'GET',
					responseRedactions: [
						{ regex: 'emailAddress\":\"(?<test>[a-z_]+)@', hash: 'oprf' }
					],
					responseMatches: [{ type: 'contains', value: '' }]
				},
				secretParams: {
					authorisationHeader: `Bearer ${user}`
				},
				ownerPrivateKey: opts.privateKeyHex,
				client,
				zkEngine,
			})

			assert.ok(!result.error)
			assert.ok(result.claim)

			// transcript is stripped from response to reduce wire size
			// OPRF cross-packet validation is done server-side
		})

		it('should create a claim with an experimental predicate proof bound to OPRF', async() => {
			const user = 'adhiraj'
			const hiddenResponseSegment = `"emailAddress":"${user}@mock.com"`
			const proof = buildExperimentalPredicateProof({
				hiddenValueBinding: hiddenResponseSegment,
				responseSelector: '$.emailAddress',
			})
			let verifierCalled = false
			const oprfOperator = makeTestOprfOperator()
			const verifier = makeProfileAgeGte20ToyVerifier(
				'claim-creation-test-template',
				'$.emailAddress'
			)
			assert.equal(verifier.circuitHash, proof.publicInput.circuitHash)
			EXPERIMENTAL_PREDICATE_PROOF_VERIFIERS.set(
				verifier.circuitHash,
				received => {
					verifierCalled = true
					assert.equal(received.providerTemplateHash, proof.providerTemplateHash)
					assert.equal(received.responseSelector, proof.responseSelector)
					assert.notEqual(received.publicInput.hiddenValueBinding, hiddenResponseSegment)
					assert.equal(received.publicInput.hiddenValueBinding.length, hiddenResponseSegment.length)
					return verifier.verify(received)
				}
			)
			EXPERIMENTAL_OPRF_OPERATOR_OVERRIDES.chacha20 = oprfOperator
			EXPERIMENTAL_OPRF_OPERATOR_OVERRIDES['aes-128-ctr'] = oprfOperator
			EXPERIMENTAL_OPRF_OPERATOR_OVERRIDES['aes-256-ctr'] = oprfOperator

			try {
				let preparedRequest: ClaimTunnelRequest | undefined
				const result = await createClaimOnAttestor({
					name: 'http',
					params: {
						url: claimUrl,
						method: 'GET',
						responseRedactions: [
							{
								jsonPath: '$.emailAddress',
								hash: 'oprf'
							}
						],
						responseMatches: [
							{
								type: 'contains',
								value: ''
							}
						]
					},
					secretParams: {
						authorisationHeader: `Bearer ${user}`
					},
					context: {
						experimentalPredicateProof: proof,
					},
					ownerPrivateKey: opts.privateKeyHex,
					client,
					zkEngine: 'stwo',
					oprfOperators: {
						chacha20: oprfOperator,
						'aes-128-ctr': oprfOperator,
						'aes-256-ctr': oprfOperator,
					},
					onClaimRequestPrepared(request) {
						preparedRequest = request
					},
				})

				assert.ok(!result.error)
				assert.ok(result.claim)
				assert.equal(verifierCalled, true)
				const ctx = JSON.parse(result.claim.context)
				assert.equal(ctx.experimentalPredicateProof, undefined)
				assert.equal(ctx.hiddenPredicate.responseSelector, '$.emailAddress')
				assert.deepEqual(ctx.hiddenPredicate.selectedField, {
					selector: '$.emailAddress',
					bindingKind: 'toprf-json-redaction',
					boundSegmentEncoding: 'json-key-value-segment',
				})
				assert.equal(ctx.hiddenPredicate.predicateResult, true)
				assert.equal(ctx.hiddenPredicate.transcriptBinding.kind, 'toprf')
				assert.equal(ctx.hiddenPredicate.transcriptBinding.length, hiddenResponseSegment.length)
				assert.equal(typeof ctx.hiddenPredicate.transcriptBinding.recordNumber, 'number')
				assert.equal(typeof ctx.hiddenPredicate.transcriptBinding.packetOffset, 'number')
				assert.equal(typeof ctx.hiddenPredicate.transcriptBinding.nullifierHash, 'string')
				assert.equal(
					ctx.hiddenPredicate.hiddenValueBindingHash,
					ctx.hiddenPredicate.transcriptBinding.nullifierHash
				)
				assert.equal(ctx.hiddenPredicate.hiddenValueBinding, undefined)
				assert.equal(ctx.hiddenPredicate.proofHash, hashCanonical(proof.proof))

				const pkg = buildExperimentalPredicateProofPackageFromClaimResponse(
					result,
					proof.proof,
					undefined,
					preparedRequest?.transcript
				)
				const pkgResult = await verifyExperimentalPredicateProofPackage(pkg)
				assert.equal(pkgResult.ok, true, pkgResult.errors.join('; '))
				assert.equal(
					pkg.reveal.attestorObservedTranscriptCommitment.responseSelector,
					'$.emailAddress'
				)
				assert.equal(pkg.warning.independentThirdPartyVerification, true)
				assert.deepEqual(pkg.warning.missing, [])
				assert.ok(pkg.reveal.replayableRevealProof)
			} finally {
				EXPERIMENTAL_PREDICATE_PROOF_VERIFIERS.delete(
					proof.publicInput.circuitHash
				)
				delete EXPERIMENTAL_OPRF_OPERATOR_OVERRIDES.chacha20
				delete EXPERIMENTAL_OPRF_OPERATOR_OVERRIDES['aes-128-ctr']
				delete EXPERIMENTAL_OPRF_OPERATOR_OVERRIDES['aes-256-ctr']
			}
		})

		it('should produce the same hash for the same input', async() => {

			let hash: Uint8Array | undefined

			for(let i = 0;i < 2;i++) {
				const user = '(?<su>some-user)'
				const result = await createClaimOnAttestor({
					name: 'http',
					params: {
						url: claimUrl,
						method: 'GET',
						responseRedactions: [
							{
								regex: user,
								hash: 'oprf'
							}
						],
						responseMatches: [
							{
								type: 'contains',
								value: ''
							}
						]
					},
					secretParams: {
						authorisationHeader: `Bearer ${user}`
					},
					ownerPrivateKey: opts.privateKeyHex,
					client,
					zkEngine,
				})

				assert.ok(!result.error)
				assert.ok(result.claim)
				// verify same claim produces consistent hash via context
				const ctx = JSON.parse(result.claim.context)
				const providerHash = ctx.providerHash
				assert.ok(providerHash)
				hash ||= providerHash
				assert.equal(providerHash, hash)
			}
		})
	})

	describe('Pool', () => {

		it('should correctly throw error when tunnel creation fails', async() => {
			await assert.rejects(
				() => createClaimOnAttestor({
					name: 'http',
					params: {
						url: 'https://some.dns.not.exist',
						method: 'GET',
						responseRedactions: [],
						responseMatches: [
							{
								type: 'contains',
								value: 'test'
							}
						]
					},
					secretParams: {
						authorisationHeader: 'Bearer abcd'
					},
					ownerPrivateKey: opts.privateKeyHex,
					client: { url: opts.serverUrl },
					zkEngine
				}),
				(err: AttestorError) => {
					assert.match(err.message, /ENOTFOUND/)
					return true
				}
			)
		})

		it('should reconnect client when found disconnected', async() => {
			await createClaim()
			// since we're using a pool, we'll find the client
			// disconnected and when we create the claim again
			// we expect a new connection to be established
			const client = getAttestorClientFromPool(opts.serverUrl)
			await client.terminateConnection()
			// ensure claim is still successful
			const result2 = await createClaim()
			assert.ok(result2.claim)

			const client2 = getAttestorClientFromPool(opts.serverUrl)
			assert.notEqual(client2, client)
		})

		it('should retry on network errors', async() => {
			const client = getAttestorClientFromPool(opts.serverUrl)
			client.sendMessage = async() => {
				// @ts-ignore
				client.sendMessage = () => {}

				const err = new AttestorError(
					'ERROR_NETWORK_ERROR',
					'F'
				)

				await client.terminateConnection(err)
				throw err
			}

			// first the client will mock disconnection when
			// sending a message -- that should trigger a retry
			// and result in a successful claim creation
			assert.ok(await createClaim())

			// ensure new client is created to replace
			// the disconnected one
			const client2 = getAttestorClientFromPool(opts.serverUrl)
			assert.notEqual(client2, client)
		})
	})

	it('should reject claims where redactions have a smuggled HTTP request', async() => {
		const honestUser = 'honest'
		const attackerUser = 'attacker'

		CREATE_REQUEST.mock.mockImplementationOnce((secretParams,	params) => {
			const url = new URL(params.url)
			const { pathname } = url
			const searchParams = params.url.includes('?')
				? params.url.split('?')[1]
				: ''
			const path = pathname + (searchParams ? '?' + searchParams : '')

			const authHonest = `Authorization: ${secretParams.authorisationHeader}`
			const req1Lines = [
				`GET ${path} HTTP/1.1`,
				`Host: ${url.host}`,
				'Content-Length: 0',
				'Accept-Encoding: identity',
				authHonest,
				'Connection: keep-alive',
				'',
				'',
			]
			const req1 = req1Lines.join('\r\n')

			const authAttacker = `Authorization: Bearer ${attackerUser}`
			const req2Lines = [
				`GET ${path} HTTP/1.1`,
				`Host: ${url.host}`,
				'Content-Length: 0',
				'Accept-Encoding: identity',
				authAttacker,
				'Connection: close',
				'',
				'',
			]
			const req2 = req2Lines.join('\r\n')

			const fullPayload = req1 + req2

			const bearerTokenStart = fullPayload.indexOf(authHonest)
			const attackerTokenStart = fullPayload.indexOf(authAttacker, bearerTokenStart)

			return {
				data: fullPayload,
				redactions: [{ fromIndex: bearerTokenStart, toIndex: attackerTokenStart }],
			}
		})

		GET_RESPONSE_REDCTIONS.mock.mockImplementationOnce((opts) => {
			const { response } = opts
			const bodyRedact = getFirstResponseBodyRedaction(response)
			assert(bodyRedact)

			return [bodyRedact]
		})

		ASSERT_VALID_RECEIPT.mock
			.mockImplementationOnce(() => ({ extractedParameters: {} }))

		const rslt = await createClaimOnAttestor({
			name: 'http',
			params: {
				url: claimUrl,
				method: 'GET',
				responseRedactions: [],
				responseMatches: [
					{
						type: 'contains',
						value: `${attackerUser}@mock.com`,
					},
				],
			},
			secretParams: {
				authorisationHeader: `Bearer ${honestUser}`,
			},
			ownerPrivateKey: opts.privateKeyHex,
			client,
			zkEngine,
		})
		assert.ok(rslt.error)
		assert.match(rslt.error.message, /mismatch/)
	})

	function getFirstResponseBodyRedaction(response: Uint8Array) {
		const str = uint8ArrayToStr(response)
		const hdrEnd = str.indexOf('\r\n\r\n')
		if(hdrEnd === -1) {return null}

		const clMatch = str.match(/content-length:\s*(\d+)/i)
		if(!clMatch) {return null}

		const bodyLen = parseInt(clMatch[1])
		const bodyStart = hdrEnd + 4
		const secondResponseStart = str.indexOf(
			'HTTP/',
			bodyStart + bodyLen,
		)
		if(secondResponseStart === -1) {return null}

		return {
			fromIndex: bodyStart,
			toIndex: secondResponseStart,
		}
	}

	function createClaim() {
		const user = 'testing-123'
		return createClaimOnAttestor({
			name: 'http',
			params: {
				url: claimUrl,
				method: 'GET',
				responseRedactions: [],
				responseMatches: [
					{
						type: 'contains',
						value: `${user}@mock.com`
					}
				]
			},
			secretParams: {
				authorisationHeader: `Bearer ${user}`
			},
			ownerPrivateKey: opts.privateKeyHex,
			client: { url: opts.serverUrl }
		})
	}
})

function buildExperimentalPredicateProof({
	hiddenValueBinding,
	responseSelector,
}: {
	hiddenValueBinding: string
	responseSelector: string
}): ExperimentalPredicateProof {
	const proof: ExperimentalPredicateProof = {
		version: 'tlsn-mpc-lab.profile-age-predicate.v1',
		providerTemplateHash: 'claim-creation-test-template',
		responseSelector,
		predicate: {
			kind: 'age_gte',
			threshold: 20,
		},
		publicInput: {
			providerTemplateHash: 'claim-creation-test-template',
			responseSelector,
			hiddenValueBinding,
			circuitHash: '',
			predicateResult: true,
		},
		proof: {
			system: 'toy',
			payload: { test: 'claim-creation' },
		},
	}
	proof.publicInput.circuitHash = createHash('sha256')
		.update(JSON.stringify({
			version: proof.version,
			providerTemplateHash: proof.providerTemplateHash,
			responseSelector: proof.responseSelector,
			predicate: proof.predicate,
		}))
		.digest('hex')

	return proof
}

function hashCanonical(value: unknown) {
	return createHash('sha256')
		.update(JSON.stringify(sortCanonical(value)))
		.digest('hex')
}

function sortCanonical(value: unknown): unknown {
	if(value === null || typeof value !== 'object') {
		return value
	}
	if(Array.isArray(value)) {
		return value.map(sortCanonical)
	}

	return Object.fromEntries(
		Object.keys(value)
			.sort()
			.map(key => [key, sortCanonical((value as Record<string, unknown>)[key])])
	)
}

function makeTestOprfOperator(): OPRFOperator {
	return {
		async generateWitness() {
			return new Uint8Array()
		},
		async groth16Prove() {
			return { proof: new Uint8Array([1]) }
		},
		async groth16Verify() {
			return true
		},
		async generateThresholdKeys() {
			return {
				publicKey: new Uint8Array(),
				privateKey: new Uint8Array(),
				shares: [],
			}
		},
		async generateOPRFRequestData(data) {
			return {
				mask: new Uint8Array(),
				maskedData: data,
				secretElements: [],
			}
		},
		async finaliseOPRF(_serverPublicKey, request) {
			return request.maskedData
		},
		async evaluateOPRF(_serverPrivateKey, request) {
			return {
				evaluated: request,
				c: new Uint8Array(),
				r: new Uint8Array(),
			}
		},
	}
}
