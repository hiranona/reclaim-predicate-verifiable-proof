import { createHash } from 'crypto'

import type {
	ExperimentalPredicateProof,
	ExperimentalPredicateProofVerifier
} from '#src/providers/http/experimental-predicate.ts'

export type ExperimentalPredicateVerifierAdapter = {
	circuitHash: string
	verify: ExperimentalPredicateProofVerifier
}

export function makeProfileAgeGte20ToyVerifier(
	templateHash: string,
	responseSelector: string
): ExperimentalPredicateVerifierAdapter {
	const circuitHash = computeProfileAgeCircuitHash(templateHash, responseSelector)
	return {
		circuitHash,
		verify(proof) {
			return verifyProfileAgeGte20ToyProof(proof, templateHash, responseSelector)
		},
	}
}

export function verifyProfileAgeGte20ToyProof(
	proof: ExperimentalPredicateProof,
	templateHash: string,
	responseSelector: string
) {
	return proof.version === 'tlsn-mpc-lab.profile-age-predicate.v1'
		&& proof.providerTemplateHash === templateHash
		&& proof.responseSelector === responseSelector
		&& proof.predicate.kind === 'age_gte'
		&& proof.predicate.threshold === 20
		&& proof.publicInput.providerTemplateHash === templateHash
		&& proof.publicInput.responseSelector === responseSelector
		&& proof.publicInput.predicateResult === true
		&& proof.publicInput.circuitHash
			=== computeProfileAgeCircuitHash(templateHash, responseSelector)
		&& proof.proof.system === 'toy'
}

export function computeProfileAgeCircuitHash(
	templateHash: string,
	responseSelector: string
) {
	return createHash('sha256')
		.update(JSON.stringify({
			version: 'tlsn-mpc-lab.profile-age-predicate.v1',
			providerTemplateHash: templateHash,
			responseSelector,
			predicate: {
				kind: 'age_gte',
				threshold: 20,
			},
		}))
		.digest('hex')
}
