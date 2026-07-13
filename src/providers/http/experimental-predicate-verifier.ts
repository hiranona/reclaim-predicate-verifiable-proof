import { createHash } from 'crypto'

import type {
	ExperimentalPredicate,
	ExperimentalPredicateProof,
	ExperimentalPredicateProofVerifier
} from '#src/providers/http/experimental-predicate.ts'

export type ExperimentalPredicateVerifierAdapter = {
	circuitHash: string
	verify: ExperimentalPredicateProofVerifier
}

export type ExperimentalPredicateVerifierChallenge = {
	proofVersion?: ExperimentalPredicateProof['version']
	templateHash: string
	responseSelector: string
	predicate: ExperimentalPredicate
	proofSystem?: string
}

export function makeDemoChallengeToyVerifier(
	challenge: ExperimentalPredicateVerifierChallenge
): ExperimentalPredicateVerifierAdapter {
	const circuitHash = computeDemoChallengeCircuitHash(challenge)
	return {
		circuitHash,
		verify(proof) {
			return verifyDemoChallengeToyProof(proof, challenge)
		},
	}
}

export function makeProfileAgeGte20ToyVerifier(
	templateHash: string,
	responseSelector: string
): ExperimentalPredicateVerifierAdapter {
	return makeDemoChallengeToyVerifier({
		templateHash,
		responseSelector,
		predicate: {
			kind: 'age_gte',
			threshold: 20,
		},
	})
}

export function verifyProfileAgeGte20ToyProof(
	proof: ExperimentalPredicateProof,
	templateHash: string,
	responseSelector: string
) {
	return verifyDemoChallengeToyProof(proof, {
		templateHash,
		responseSelector,
		predicate: {
			kind: 'age_gte',
			threshold: 20,
		},
	})
}

export function computeProfileAgeCircuitHash(
	templateHash: string,
	responseSelector: string
) {
	return computeDemoChallengeCircuitHash({
		templateHash,
		responseSelector,
		predicate: {
			kind: 'age_gte',
			threshold: 20,
		},
	})
}

export function verifyDemoChallengeToyProof(
	proof: ExperimentalPredicateProof,
	challenge: ExperimentalPredicateVerifierChallenge
) {
	const proofVersion = challenge.proofVersion
		|| 'tlsn-mpc-lab.profile-age-predicate.v1'
	const proofSystem = challenge.proofSystem || 'toy'
	return proof.version === proofVersion
		&& proof.providerTemplateHash === challenge.templateHash
		&& proof.responseSelector === challenge.responseSelector
		&& samePredicate(proof.predicate, challenge.predicate)
		&& proof.publicInput.providerTemplateHash === challenge.templateHash
		&& proof.publicInput.responseSelector === challenge.responseSelector
		&& proof.publicInput.predicateResult === true
		&& proof.publicInput.circuitHash
			=== computeDemoChallengeCircuitHash(challenge)
		&& proof.proof.system === proofSystem
}

export function computeDemoChallengeCircuitHash(
	challenge: ExperimentalPredicateVerifierChallenge
) {
	const proofVersion = challenge.proofVersion
		|| 'tlsn-mpc-lab.profile-age-predicate.v1'
	return createHash('sha256')
		.update(JSON.stringify({
			version: proofVersion,
			providerTemplateHash: challenge.templateHash,
			responseSelector: challenge.responseSelector,
			predicate: challenge.predicate,
		}))
		.digest('hex')
}

function samePredicate(
	a: ExperimentalPredicate,
	b: ExperimentalPredicate
) {
	return JSON.stringify(a) === JSON.stringify(b)
}
