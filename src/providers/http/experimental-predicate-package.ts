import { createHash } from 'crypto'
import { hexlify } from 'ethers'

import type {
	ExperimentalPredicateProof,
	HiddenPredicateStatement
} from '#src/providers/http/experimental-predicate.ts'
import {
	ServiceSignatureType,
	type ClaimTunnelRequest_TranscriptMessage,
	type ClaimTunnelResponse,
	type ProviderClaimData
} from '#src/proto/api.ts'
import {
	canonicalStringify,
	createSignDataForClaim,
	getIdentifierFromClaimInfo,
	strToUint8Array
} from '#src/utils/index.ts'
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
		missing: Array<'reveal.replayableRevealProof'>
	}
}

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
		recordNumber: number
		packetOffset: number
		length: number
		zkReveal: ClaimTunnelRequest_TranscriptMessage['reveal']['zkReveal']
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
			independentThirdPartyVerification: Boolean(replayableRevealProof),
			missing: replayableRevealProof ? [] : ['reveal.replayableRevealProof'],
		},
	}
}

export function buildExperimentalPredicateProofPackageFromClaimResponse(
	response: Pick<ClaimTunnelResponse, 'claim' | 'signatures'>,
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

		verifyReplayableRevealProof(pkg, hiddenPredicate, errors)
	}

	return {
		ok: errors.length === 0,
		errors,
		hiddenPredicate,
		limitations: [
			'This package verifies the attestor claim signature, signed-context shape, predicate proof hash, transcript commitment, and replayable reveal proof binding.',
			'It does not run the underlying Reclaim ZK verifier unless the caller replays the bundled zkReveal with verifyZkPacket and the original TLS record material.',
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
		.update(canonicalStringify(value) || 'null')
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
			recordNumber: hiddenPredicate.transcriptBinding.recordNumber,
			packetOffset: hiddenPredicate.transcriptBinding.packetOffset,
			length: hiddenPredicate.transcriptBinding.length,
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

function verifyReplayableRevealProof(
	pkg: ExperimentalPredicateProofPackage,
	hiddenPredicate: HiddenPredicateStatement,
	errors: string[]
) {
	const replayProof = pkg.reveal?.replayableRevealProof
	if(!replayProof) {
		if(pkg.warning?.independentThirdPartyVerification !== false) {
			errors.push('package without replayable reveal proof must declare independentThirdPartyVerification=false')
		}
		if(!pkg.warning?.missing?.includes('reveal.replayableRevealProof')) {
			errors.push('package without replayable reveal proof must list reveal.replayableRevealProof as missing')
		}
		return
	}

	if(pkg.warning?.independentThirdPartyVerification !== true) {
		errors.push('package with replayable reveal proof must declare independentThirdPartyVerification=true')
	}
	if(pkg.warning?.missing?.length) {
		errors.push('package with replayable reveal proof must not list missing reveal items')
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
	)
}
