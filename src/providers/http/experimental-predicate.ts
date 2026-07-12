import { createHash } from 'crypto'

import type {
	HiddenValueBinding,
	ProviderCtx,
	ProviderParams,
} from '#src/types/index.ts'
import { canonicalStringify } from '#src/utils/index.ts'

type HTTPProviderParams = ProviderParams<'http'>

export type ExperimentalPredicateProof = {
	version: 'tlsn-mpc-lab.profile-age-predicate.v1'
	providerTemplateHash: string
	responseSelector: string
	predicate: {
		kind: 'age_gte'
		threshold: number
	}
	publicInput: {
		providerTemplateHash: string
		responseSelector: string
		hiddenValueBinding: string
		circuitHash: string
		predicateResult: boolean
	}
	proof: {
		system: string
		payload: unknown
	}
}

export type ExperimentalPredicateProofVerifier = (
	proof: ExperimentalPredicateProof
) => Promise<boolean> | boolean

export type HiddenPredicateStatement = {
	version: 'tlsn-mpc-lab.hidden-predicate-statement.v1'
	templateHash: string
	responseSelector: string
	selectedField: {
		selector: string
		bindingKind: 'toprf-json-redaction'
		boundSegmentEncoding: 'json-key-value-segment'
	}
	hiddenValueBindingHash: string
	transcriptBinding: {
		kind: 'toprf'
		recordNumber: number
		packetOffset: number
		length: number
		nullifierHash: string
		cipherSuite: string
		ciphertextHash: string
	}
	predicate: ExperimentalPredicateProof['predicate']
	predicateResult: true
	proofSystem: string
	proofHash: string
}

export type PredicateProviderCtx = ProviderCtx & {
	experimentalPredicateProofVerifier?: ExperimentalPredicateProofVerifier
}

export async function assertExperimentalPredicateProof(
	params: HTTPProviderParams,
	ctx: PredicateProviderCtx
): Promise<HiddenPredicateStatement | undefined> {
	const claimContext = ctx.claimContext || {}
	const proof = claimContext.experimentalPredicateProof as unknown
	if(proof === undefined) {
		return undefined
	}

	assertPredicateProofShape(proof)

	const expectedSelector = getExpectedSelector(params)
	if(proof.responseSelector !== expectedSelector) {
		throw new Error(
			`Predicate proof selector mismatch: expected ${expectedSelector}, got ${proof.responseSelector}`
		)
	}

	if(proof.publicInput.responseSelector !== proof.responseSelector) {
		throw new Error('Predicate proof public input selector mismatch')
	}

	if(proof.publicInput.providerTemplateHash !== proof.providerTemplateHash) {
		throw new Error('Predicate proof public input template hash mismatch')
	}

	if(proof.publicInput.circuitHash !== computeCircuitHash(proof)) {
		throw new Error('Predicate proof circuit hash mismatch')
	}

	if(
		proof.predicate.kind !== 'age_gte'
		|| proof.predicate.threshold !== 20
		|| proof.publicInput.predicateResult !== true
	) {
		throw new Error('Unsupported or false predicate proof claim')
	}

	const hiddenBinding = findHiddenBinding(
		ctx.hiddenValueBindings || [],
		proof.publicInput.hiddenValueBinding
	)
	if(!hiddenBinding) {
		throw new Error(
			'Predicate proof hidden witness is not bound to a verified TOPRF reveal'
			+ `; proofLength=${proof.publicInput.hiddenValueBinding.length}`
			+ `; availableBindings=${(ctx.hiddenValueBindings || []).length}`
		)
	}

	const verifier = ctx.experimentalPredicateProofVerifier
	if(!verifier) {
		throw new Error('No experimental predicate proof verifier configured')
	}

	const verified = await verifier(proof)
	if(!verified) {
		throw new Error('Predicate proof verification failed')
	}

	return buildHiddenPredicateStatement(proof, hiddenBinding)
}

function assertPredicateProofShape(
	proof: unknown
): asserts proof is ExperimentalPredicateProof {
	if(!proof || typeof proof !== 'object') {
		throw new Error('Invalid predicate proof context')
	}

	const p = proof as Partial<ExperimentalPredicateProof>
	if(
		p.version !== 'tlsn-mpc-lab.profile-age-predicate.v1'
		|| typeof p.providerTemplateHash !== 'string'
		|| typeof p.responseSelector !== 'string'
		|| !p.predicate
		|| !p.publicInput
		|| !p.proof
	) {
		throw new Error('Invalid predicate proof context')
	}
}

function getExpectedSelector(params: HTTPProviderParams) {
	const firstHashedJsonRedaction = params.responseRedactions?.find(
		r => r.jsonPath && r.hash === 'oprf'
	)
	if(!firstHashedJsonRedaction?.jsonPath) {
		throw new Error('Predicate proof requires a hashed JSON response redaction')
	}

	return firstHashedJsonRedaction.jsonPath
}

function findHiddenBinding(bindings: HiddenValueBinding[], nullifierText: string) {
	return bindings.find(
		b => b.kind === 'toprf'
			&& b.nullifierText === nullifierText
	)
}

function computeCircuitHash(proof: ExperimentalPredicateProof) {
	return createHash('sha256')
		.update(JSON.stringify({
			version: proof.version,
			providerTemplateHash: proof.providerTemplateHash,
			responseSelector: proof.responseSelector,
			predicate: proof.predicate,
		}))
		.digest('hex')
}

function buildHiddenPredicateStatement(
	proof: ExperimentalPredicateProof,
	hiddenBinding: HiddenValueBinding
): HiddenPredicateStatement {
	return {
		version: 'tlsn-mpc-lab.hidden-predicate-statement.v1',
		templateHash: proof.providerTemplateHash,
		responseSelector: proof.responseSelector,
		selectedField: {
			selector: proof.responseSelector,
			bindingKind: 'toprf-json-redaction',
			boundSegmentEncoding: 'json-key-value-segment',
		},
		hiddenValueBindingHash: hashCanonical(proof.publicInput.hiddenValueBinding),
		transcriptBinding: {
			kind: hiddenBinding.kind,
			recordNumber: hiddenBinding.recordNumber,
			packetOffset: hiddenBinding.packetOffset,
			length: hiddenBinding.length,
			nullifierHash: hashCanonical(hiddenBinding.nullifierText),
			cipherSuite: hiddenBinding.cipherSuite,
			ciphertextHash: hiddenBinding.ciphertextHash,
		},
		predicate: proof.predicate,
		predicateResult: true,
		proofSystem: proof.proof.system,
		proofHash: hashCanonical(proof.proof),
	}
}

function hashCanonical(value: unknown) {
	return createHash('sha256')
		.update(canonicalStringify(value as { [key: string]: any }) || 'null')
		.digest('hex')
}
