import { createHash } from 'crypto'
import type { CipherSuite } from '@reclaimprotocol/tls'
import { hexlify } from 'ethers'

import type {
	ExperimentalPredicateProof,
	HiddenPredicateStatement
} from '#src/providers/http/experimental-predicate.ts'
import {
	ClaimTunnelResponse,
	ServiceSignatureType,
	type ClaimTunnelRequest_TranscriptMessage,
	type ClaimTunnelRequest,
	type MessageReveal,
	type ProviderClaimData
} from '#src/proto/api.ts'
import { TranscriptMessageSenderType } from '#src/proto/api.ts'
import {
	canonicalStringify,
	createSignDataForClaim,
	getIdentifierFromClaimInfo,
	strToUint8Array
} from '#src/utils/index.ts'
import { getEngineString, verifyZkPacket } from '#src/utils/zk.ts'
import { SIGNATURES } from '#src/utils/signatures/index.ts'

export type ExperimentalPredicateProofPackage = {
	version: 'tlsn-mpc-lab.reclaim-hidden-predicate-package.v1'
	claim: Pick<
		ProviderClaimData,
		'provider' | 'parameters' | 'context' | 'identifier' | 'owner' | 'timestampS' | 'epoch'
	>
	attestation?: {
		signatureType: ServiceSignatureType
		attestorAddress: string
		claimSignature: string
		resultSignature?: string
		signedRequest?: ClaimTunnelRequest
	}
	claimSigningPayload: {
		format: 'reclaim.createSignDataForClaim.v1'
		identifier: string
		sha256: string
	}
	reveal: {
		attestorObservedTranscriptCommitment: AttestorObservedTranscriptCommitment
		replayableRevealProof?: ReplayableRevealProof
	}
	predicateProof: ExperimentalPredicateProof['proof']
	warning: {
		independentThirdPartyVerification: boolean
		missing: ExperimentalPredicateProofPackageMissing[]
	}
}

export type ExperimentalPredicateProofPackageMissing =
	| 'reveal.replayableRevealProof'
	| 'reveal.attestorObservedCiphertext'
	| 'attestation.resultSignature'
	| 'attestation.signedRequest'

export type AttestorObservedTranscriptCommitment = {
	kind: 'reclaim.toprf.transcript-binding.v1'
	claimIdentifier: string
	provider: string
	responseSelector: string
	selectedField: HiddenPredicateStatement['selectedField']
	transcriptBinding: HiddenPredicateStatement['transcriptBinding']
	commitmentHash: string
}

export type ReplayableRevealProof = {
	kind: 'reclaim.zk-toprf-reveal.v1'
	claimIdentifier: string
	records: Array<{
		transcriptIndex: number
		sender: TranscriptMessageSenderType
		recordNumber: number
		packetOffset: number
		length: number
		ciphertext: string
		zkReveal: MessageReveal['zkReveal']
	}>
	proofHash: string
}

export function buildExperimentalPredicateProofPackage(
	claim: ExperimentalPredicateProofPackage['claim'],
	predicateProof: ExperimentalPredicateProof['proof'],
	attestation?: ExperimentalPredicateProofPackage['attestation'],
	transcript?: ClaimTunnelRequest_TranscriptMessage[]
): ExperimentalPredicateProofPackage {
	const hiddenPredicate = parseContext(claim.context, [])
		?.hiddenPredicate as HiddenPredicateStatement | undefined
	const replayableRevealProof = transcript && hiddenPredicate
		? buildReplayableRevealProof(claim, hiddenPredicate, transcript)
		: undefined
	const missing = getMissingIndependentVerificationItems(
		replayableRevealProof,
		attestation
	)
	return {
		version: 'tlsn-mpc-lab.reclaim-hidden-predicate-package.v1',
		claim,
		attestation,
		claimSigningPayload: buildClaimSigningPayload(claim),
		reveal: {
			attestorObservedTranscriptCommitment:
				buildAttestorObservedTranscriptCommitment(claim, hiddenPredicate),
			replayableRevealProof,
		},
		predicateProof,
		warning: {
			independentThirdPartyVerification: missing.length === 0,
			missing,
		},
	}
}

export function buildExperimentalPredicateProofPackageFromClaimResponse(
	response: Pick<ClaimTunnelResponse, 'claim' | 'request' | 'signatures'>,
	predicateProof: ExperimentalPredicateProof['proof'],
	signatureType = ServiceSignatureType.SERVICE_SIGNATURE_TYPE_ETH,
	transcript?: ClaimTunnelRequest_TranscriptMessage[]
) {
	if(!response.claim) {
		throw new Error('claim response is missing claim')
	}
	if(!response.signatures) {
		throw new Error('claim response is missing signatures')
	}

	return buildExperimentalPredicateProofPackage(
		response.claim,
		predicateProof,
		{
			signatureType,
			attestorAddress: response.signatures.attestorAddress,
			claimSignature: hexlify(response.signatures.claimSignature),
			resultSignature: response.signatures.resultSignature?.length
				? hexlify(response.signatures.resultSignature)
				: undefined,
			signedRequest: response.request,
		},
		transcript
	)
}

export async function verifyExperimentalPredicateProofPackage(
	pkg: ExperimentalPredicateProofPackage
) {
	const errors: string[] = []
	if(pkg.version !== 'tlsn-mpc-lab.reclaim-hidden-predicate-package.v1') {
		errors.push(`unexpected package version: ${pkg.version}`)
	}
	const computedIdentifier = computeClaimIdentifier(pkg.claim, errors)
	if(computedIdentifier && pkg.claim?.identifier !== computedIdentifier) {
		errors.push('claim identifier does not match provider, parameters, and context')
	}

	const signingPayload = pkg.claim
		? buildClaimSigningPayload(pkg.claim)
		: undefined
	if(signingPayload) {
		if(pkg.claimSigningPayload?.format !== signingPayload.format) {
			errors.push('claim signing payload format mismatch')
		}
		if(pkg.claimSigningPayload?.identifier !== signingPayload.identifier) {
			errors.push('claim signing payload identifier mismatch')
		}
		if(pkg.claimSigningPayload?.sha256 !== signingPayload.sha256) {
			errors.push('claim signing payload hash mismatch')
		}
	}

	await verifyClaimSignature(pkg, errors)

	const context = parseContext(pkg.claim?.context, errors)
	const hiddenPredicate = context?.hiddenPredicate as HiddenPredicateStatement | undefined
	if(!hiddenPredicate) {
		errors.push('claim context is missing hiddenPredicate')
	} else if(hiddenPredicate.proofHash !== hashCanonical(pkg.predicateProof)) {
		errors.push('predicate proof hash does not match signed hiddenPredicate statement')
	} else if(!hasCompleteHiddenPredicateStatement(hiddenPredicate)) {
		errors.push('claim context has incomplete hiddenPredicate transcript binding')
	} else {
		if(
			hiddenPredicate.transcriptBinding.nullifierHash
			!== hiddenPredicate.hiddenValueBindingHash
		) {
			errors.push('hiddenPredicate nullifier hash does not match hidden value binding')
		}

		const expectedCommitment
			= buildAttestorObservedTranscriptCommitment(pkg.claim, hiddenPredicate)
		if(
			canonicalStringify(pkg.reveal?.attestorObservedTranscriptCommitment)
			!== canonicalStringify(expectedCommitment)
		) {
			errors.push('attestor observed transcript commitment mismatch')
		}

		await verifyReplayableRevealProof(pkg, hiddenPredicate, errors)
	}

	return {
		ok: errors.length === 0,
		errors,
		hiddenPredicate,
		limitations: [
			'This package verifies the attestor claim signature, signed result signature when present, signed-context shape, predicate proof hash, transcript commitment, replayable reveal proof binding, and ciphertext hash binding.',
			pkg.warning?.independentThirdPartyVerification
				? 'The package includes enough material for this verifier to rerun Reclaim ZK/TOPRF verification for the signed hidden transcript range.'
				: 'The package does not include enough material to independently rerun Reclaim ZK/TOPRF verification for the signed hidden transcript range.',
		],
	}
}

function computeClaimIdentifier(
	claim: ExperimentalPredicateProofPackage['claim'] | undefined,
	errors: string[]
) {
	if(!claim) {
		errors.push('package is missing claim')
		return undefined
	}

	try {
		return getIdentifierFromClaimInfo({ ...claim })
	} catch(err) {
		errors.push(`claim identifier cannot be computed: ${(err as Error).message}`)
		return undefined
	}
}

async function verifyClaimSignature(
	pkg: ExperimentalPredicateProofPackage,
	errors: string[]
) {
	if(!pkg.attestation) {
		errors.push('package is missing attestor claim signature')
		return
	}
	if(!pkg.claim) {
		return
	}

	const verifier = SIGNATURES[pkg.attestation.signatureType]
	if(!verifier) {
		errors.push(`unsupported signature type: ${pkg.attestation.signatureType}`)
		return
	}

	const verified = await verifier.verify(
		strToUint8Array(createSignDataForClaim({ ...pkg.claim })),
		pkg.attestation.claimSignature,
		pkg.attestation.attestorAddress
	)
	if(!verified) {
		errors.push('invalid attestor claim signature')
	}
}

async function verifyResultSignature(
	pkg: ExperimentalPredicateProofPackage,
	errors: string[]
) {
	if(!pkg.attestation?.resultSignature || !pkg.attestation?.signedRequest) {
		return
	}

	const verifier = SIGNATURES[pkg.attestation.signatureType]
	if(!verifier) {
		return
	}

	const signedResponse = ClaimTunnelResponse.create({
		request: reviveUint8Arrays(pkg.attestation.signedRequest),
		claim: pkg.claim,
	})
	const verified = await verifier.verify(
		ClaimTunnelResponse.encode(signedResponse).finish(),
		pkg.attestation.resultSignature,
		pkg.attestation.attestorAddress
	)
	if(!verified) {
		errors.push('invalid attestor result signature')
	}
}

function parseContext(context: string | undefined, errors: string[]) {
	if(!context) {
		errors.push('claim is missing context')
		return undefined
	}

	try {
		return JSON.parse(context)
	} catch(err) {
		errors.push(`claim context is not JSON: ${(err as Error).message}`)
		return undefined
	}
}

function hashCanonical(value: unknown) {
	return createHash('sha256')
		.update(canonicalStringify(value as { [key: string]: any }) || 'null')
		.digest('hex')
}

function buildClaimSigningPayload(claim: ExperimentalPredicateProofPackage['claim']) {
	const signData = createSignDataForClaim({ ...claim })
	return {
		format: 'reclaim.createSignDataForClaim.v1' as const,
		identifier: claim.identifier,
		sha256: createHash('sha256')
			.update(signData)
			.digest('hex'),
	}
}

function buildAttestorObservedTranscriptCommitment(
	claim: ExperimentalPredicateProofPackage['claim'],
	hiddenPredicate?: HiddenPredicateStatement
): AttestorObservedTranscriptCommitment {
	if(!hiddenPredicate || !hasCompleteHiddenPredicateStatement(hiddenPredicate)) {
		throw new Error('claim context is missing complete hiddenPredicate')
	}

	const commitment = {
		kind: 'reclaim.toprf.transcript-binding.v1' as const,
		claimIdentifier: claim.identifier,
		provider: claim.provider,
		responseSelector: hiddenPredicate.responseSelector,
		selectedField: hiddenPredicate.selectedField,
		transcriptBinding: hiddenPredicate.transcriptBinding,
	}

	return {
		...commitment,
		commitmentHash: hashCanonical(commitment),
	}
}

function buildReplayableRevealProof(
	claim: ExperimentalPredicateProofPackage['claim'],
	hiddenPredicate: HiddenPredicateStatement,
	transcript: ClaimTunnelRequest_TranscriptMessage[]
): ReplayableRevealProof {
	const records = transcript
		.map((message, transcriptIndex) => ({ message, transcriptIndex }))
		.filter(({ message }) => message.reveal?.zkReveal?.toprfs?.some(
			toprf => {
				const dataLocation = toprf.payload?.dataLocation
				return dataLocation
					&& dataLocation.length === hiddenPredicate.transcriptBinding.length
					&& toprf.startIdx + dataLocation.fromIndex
						=== hiddenPredicate.transcriptBinding.packetOffset
			}
		))
		.map(({ message, transcriptIndex }) => ({
			transcriptIndex,
			sender: message.sender,
			recordNumber: hiddenPredicate.transcriptBinding.recordNumber,
			packetOffset: hiddenPredicate.transcriptBinding.packetOffset,
			length: hiddenPredicate.transcriptBinding.length,
			ciphertext: bytesToHex(getWithoutHeader(message.message)),
			zkReveal: message.reveal!.zkReveal,
		}))

	if(!records.length) {
		throw new Error('transcript is missing replayable TOPRF reveal proof')
	}

	const replayProof = {
		kind: 'reclaim.zk-toprf-reveal.v1' as const,
		claimIdentifier: claim.identifier,
		records,
	}

	return {
		...replayProof,
		proofHash: hashCanonical(replayProof),
	}
}

async function verifyReplayableRevealProof(
	pkg: ExperimentalPredicateProofPackage,
	hiddenPredicate: HiddenPredicateStatement,
	errors: string[]
) {
	const replayProof = pkg.reveal?.replayableRevealProof
	const expectedMissing = getMissingIndependentVerificationItems(
		replayProof,
		pkg.attestation
	)
	if(pkg.warning?.independentThirdPartyVerification !== (expectedMissing.length === 0)) {
		errors.push('independentThirdPartyVerification warning does not match bundled verification material')
	}
	for(const item of expectedMissing) {
		if(!pkg.warning?.missing?.includes(item)) {
			errors.push(`package must list ${item} as missing`)
		}
	}

	if(!replayProof) {
		if(!pkg.warning?.missing?.includes('reveal.replayableRevealProof')) {
			errors.push('package without replayable reveal proof must list reveal.replayableRevealProof as missing')
		}
		return
	}

	if(pkg.warning?.missing?.includes('reveal.replayableRevealProof')) {
		errors.push('package with replayable reveal proof must not list reveal.replayableRevealProof as missing')
	}
	if(replayProof.claimIdentifier !== pkg.claim.identifier) {
		errors.push('replayable reveal proof claim identifier mismatch')
	}

	const { proofHash, ...unsignedReplayProof } = replayProof
	if(proofHash !== hashCanonical(unsignedReplayProof)) {
		errors.push('replayable reveal proof hash mismatch')
	}

	const matchingRecord = replayProof.records.find(record =>
		record.recordNumber === hiddenPredicate.transcriptBinding.recordNumber
		&& record.packetOffset === hiddenPredicate.transcriptBinding.packetOffset
		&& record.length === hiddenPredicate.transcriptBinding.length
		&& record.zkReveal?.toprfs?.some(toprf => {
			const dataLocation = toprf.payload?.dataLocation
			return dataLocation
				&& toprf.startIdx + dataLocation.fromIndex
					=== hiddenPredicate.transcriptBinding.packetOffset
				&& dataLocation.length === hiddenPredicate.transcriptBinding.length
		})
	)
	if(!matchingRecord) {
		errors.push('replayable reveal proof does not bind the signed transcript range')
		return
	}

	if(
		hiddenPredicate.transcriptBinding.ciphertextHash
		!== hashBytes(hexToBytes(matchingRecord.ciphertext))
	) {
		errors.push('replayable reveal ciphertext hash does not match signed transcript binding')
		return
	}

	if(!expectedMissing.length) {
		await verifyResultSignature(pkg, errors)
		await verifyReplayableZkPacket(pkg, hiddenPredicate, matchingRecord, errors)
	}
}

function hasCompleteHiddenPredicateStatement(
	hiddenPredicate: HiddenPredicateStatement
) {
	return Boolean(
		hiddenPredicate.hiddenValueBindingHash
		&& hiddenPredicate.selectedField
		&& hiddenPredicate.transcriptBinding
		&& hiddenPredicate.transcriptBinding.kind === 'toprf'
		&& typeof hiddenPredicate.transcriptBinding.recordNumber === 'number'
		&& typeof hiddenPredicate.transcriptBinding.packetOffset === 'number'
		&& typeof hiddenPredicate.transcriptBinding.length === 'number'
		&& typeof hiddenPredicate.transcriptBinding.nullifierHash === 'string'
		&& typeof hiddenPredicate.transcriptBinding.cipherSuite === 'string'
		&& typeof hiddenPredicate.transcriptBinding.ciphertextHash === 'string'
	)
}

async function verifyReplayableZkPacket(
	pkg: ExperimentalPredicateProofPackage,
	hiddenPredicate: HiddenPredicateStatement,
	record: ReplayableRevealProof['records'][number],
	errors: string[]
) {
	const signedRequest = pkg.attestation?.signedRequest
	if(!signedRequest) {
		return
	}
	const revivedSignedRequest = reviveUint8Arrays(signedRequest)

	const iv = record.sender === TranscriptMessageSenderType
		.TRANSCRIPT_MESSAGE_SENDER_TYPE_SERVER
		? revivedSignedRequest.fixedServerIV
		: revivedSignedRequest.fixedClientIV
	try {
		const result = await verifyZkPacket({
			ciphertext: hexToBytes(record.ciphertext),
			zkReveal: reviveUint8Arrays(record.zkReveal),
			iv: reviveUint8Array(iv),
			recordNumber: record.recordNumber,
			cipherSuite: hiddenPredicate.transcriptBinding.cipherSuite as CipherSuite,
			zkEngine: getEngineString(revivedSignedRequest.zkEngine),
			getNextPacket() {
				return undefined
			},
		})
		const expectedNullifierHash = hiddenPredicate.transcriptBinding.nullifierHash
		const matchingBinding = result.hiddenValueBindings.find(binding =>
			binding.kind === 'toprf'
			&& binding.recordNumber === hiddenPredicate.transcriptBinding.recordNumber
			&& binding.packetOffset === hiddenPredicate.transcriptBinding.packetOffset
			&& binding.length === hiddenPredicate.transcriptBinding.length
			&& binding.ciphertextHash === hiddenPredicate.transcriptBinding.ciphertextHash
			&& hashCanonical(binding.nullifierText) === expectedNullifierHash
		)
		if(!matchingBinding) {
			errors.push('replayed ZK/TOPRF proof does not reproduce the signed hidden transcript binding')
		}
	} catch(err) {
		errors.push(`replayed ZK/TOPRF verification failed: ${(err as Error).message}`)
	}
}

function getMissingIndependentVerificationItems(
	replayProof: ReplayableRevealProof | undefined,
	attestation: ExperimentalPredicateProofPackage['attestation'] | undefined
): ExperimentalPredicateProofPackageMissing[] {
	const missing: ExperimentalPredicateProofPackageMissing[] = []
	if(!replayProof) {
		missing.push('reveal.replayableRevealProof')
	} else if(!replayProof.records.every(record => record.ciphertext)) {
		missing.push('reveal.attestorObservedCiphertext')
	}

	if(!attestation?.resultSignature) {
		missing.push('attestation.resultSignature')
	}
	if(!attestation?.signedRequest) {
		missing.push('attestation.signedRequest')
	}

	return missing
}

function getWithoutHeader(message: Uint8Array) {
	if(message.length < 5) {
		return message
	}

	const length = (message[3] << 8) + message[4]
	if(message.length < 5 + length) {
		return message.slice(5)
	}

	return message.slice(5, 5 + length)
}

function bytesToHex(value: Uint8Array) {
	return Buffer.from(value).toString('hex')
}

function hexToBytes(value: string) {
	return new Uint8Array(Buffer.from(value, 'hex'))
}

function hashBytes(value: Uint8Array) {
	return createHash('sha256')
		.update(value)
		.digest('hex')
}

function reviveUint8Array(value: unknown): Uint8Array {
	if(value instanceof Uint8Array) {
		return value
	}
	if(Array.isArray(value)) {
		return new Uint8Array(value)
	}
	if(value && typeof value === 'object') {
		const entries = Object.entries(value as Record<string, number>)
		if(entries.every(([key, item]) => /^\d+$/.test(key) && typeof item === 'number')) {
			return new Uint8Array(
				entries
					.sort(([a], [b]) => Number(a) - Number(b))
					.map(([, item]) => item)
			)
		}
	}

	return new Uint8Array()
}

function reviveUint8Arrays<T>(value: T): T {
	if(value instanceof Uint8Array) {
		return value
	}
	if(Array.isArray(value)) {
		return value.map(item => reviveUint8Arrays(item)) as T
	}
	if(value && typeof value === 'object') {
		const entries = Object.entries(value as Record<string, unknown>)
		if(entries.length && entries.every(([key, item]) => /^\d+$/.test(key) && typeof item === 'number')) {
			return reviveUint8Array(value) as T
		}

		return Object.fromEntries(
			entries.map(([key, item]) => [key, reviveUint8Arrays(item)])
		) as T
	}

	return value
}
