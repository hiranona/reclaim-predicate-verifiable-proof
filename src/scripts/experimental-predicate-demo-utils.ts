import { readFileSync } from 'fs'

import type { OPRFOperator } from '@reclaimprotocol/zk-symmetric-crypto'

import type { ExperimentalPredicateProof } from '#src/providers/http/experimental-predicate.ts'
import { computeDemoChallengeCircuitHash } from '#src/providers/http/experimental-predicate-verifier.ts'
import { EXPERIMENTAL_OPRF_OPERATOR_OVERRIDES } from '#src/utils/index.ts'

export const DEMO_TEMPLATE_HASH = 'experimental-predicate-demo-profile-v1'
export const DEMO_RESPONSE_SELECTOR = '$.age'
export const DEMO_PREDICATE = {
	kind: 'age_gte' as const,
	threshold: 20,
}
export const DEMO_PROOF_VERSION = 'tlsn-mpc-lab.profile-age-predicate.v1'

export type DemoName = 'age' | 'income'

export type DemoChallenge = {
	name: DemoName
	title: string
	endpoint: string
	outputFileName: string
	templateHash: string
	responseSelector: string
	predicate: ExperimentalPredicateProof['predicate']
	proofPayloadDemo: string
	defaultBody: Record<string, unknown>
	selectedValueKey: string
	statement: string
}

export const DEMO_CHALLENGES = {
	age: {
		name: 'age',
		title: 'Demo 1: Alice age proof',
		endpoint: '/profile',
		outputFileName: 'client-observed-profile.json',
		templateHash: DEMO_TEMPLATE_HASH,
		responseSelector: DEMO_RESPONSE_SELECTOR,
		predicate: DEMO_PREDICATE,
		proofPayloadDemo: 'profile-age-gte-20',
		defaultBody: {
			name: 'alice',
			age: 25,
			height: 170,
		},
		selectedValueKey: 'age',
		statement: '$.age satisfies age >= 20',
	},
	income: {
		name: 'income',
		title: 'Demo 2: Bob income proof',
		endpoint: '/income',
		outputFileName: 'client-observed-income.json',
		templateHash: 'experimental-predicate-demo-income-v1',
		responseSelector: '$.annualIncome',
		predicate: {
			kind: 'income_gte' as const,
			threshold: 50000,
			currency: 'USD' as const,
		},
		proofPayloadDemo: 'income-gte-50000-usd',
		defaultBody: {
			name: 'bob',
			annualIncome: 85000,
			currency: 'USD',
			employer: 'example-corp',
		},
		selectedValueKey: 'annualIncome',
		statement: '$.annualIncome satisfies annualIncome >= 50000 USD',
	},
} satisfies Record<DemoName, DemoChallenge>

export function getArg(name: string, fallback?: string) {
	const index = process.argv.indexOf(`--${name}`)
	if(index === -1) {
		return fallback
	}

	const value = process.argv[index + 1]
	if(!value || value.startsWith('--')) {
		throw new Error(`--${name} requires a value`)
	}

	return value
}

export function getDemoChallenge() {
	const demo = getArg('demo', 'age') as DemoName
	const challenge = DEMO_CHALLENGES[demo]
	if(!challenge) {
		throw new Error(`unsupported --demo ${demo}; expected age or income`)
	}

	return challenge
}

export type DemoProfile = {
	name: string
	age: number
	height: number
}

export function assertDemoProfile(value: unknown): asserts value is DemoProfile {
	if(!value || typeof value !== 'object') {
		throw new Error('profile must be an object')
	}

	const profile = value as Partial<DemoProfile>
	if(
		typeof profile.name !== 'string'
		|| !Number.isInteger(profile.age)
		|| typeof profile.height !== 'number'
	) {
		throw new Error('profile must contain name:string, age:integer, height:number')
	}
}

export function buildDemoPredicateProof(profile: DemoProfile): ExperimentalPredicateProof {
	return buildDemoPredicateProofForChallenge(DEMO_CHALLENGES.age, profile)
}

export function assertDemoResponse(
	challenge: DemoChallenge,
	value: unknown
): asserts value is Record<string, unknown> {
	if(!value || typeof value !== 'object') {
		throw new Error('demo response must be an object')
	}

	const response = value as Record<string, unknown>
	const selectedValue = response[challenge.selectedValueKey]
	if(typeof response.name !== 'string' || typeof selectedValue !== 'number') {
		throw new Error(
			`demo response must contain name:string and ${challenge.selectedValueKey}:number`
		)
	}

	if(challenge.name === 'age') {
		assertDemoProfile(value)
		return
	}

	if(response.currency !== 'USD') {
		throw new Error('income demo response must contain currency:"USD"')
	}
}

export function buildDemoPredicateProofForChallenge(
	challenge: DemoChallenge,
	response: Record<string, unknown>
): ExperimentalPredicateProof {
	assertDemoResponse(challenge, response)
	const selectedValue = response[challenge.selectedValueKey] as number
	if(!satisfiesDemoPredicate(challenge, response)) {
		throw new Error(
			`demo response does not satisfy predicate: ${challenge.statement}`
		)
	}

	const proof: ExperimentalPredicateProof = {
		version: DEMO_PROOF_VERSION,
		providerTemplateHash: challenge.templateHash,
		responseSelector: challenge.responseSelector,
		predicate: challenge.predicate,
		publicInput: {
			providerTemplateHash: challenge.templateHash,
			responseSelector: challenge.responseSelector,
			hiddenValueBinding: getDemoHiddenValueBinding(challenge, selectedValue),
			circuitHash: '',
			predicateResult: true,
		},
		proof: {
			system: 'toy',
			payload: {
				demo: challenge.proofPayloadDemo,
			},
		},
	}
	proof.publicInput.circuitHash = computeDemoCircuitHash(challenge)

	return proof
}

export function computeDemoCircuitHash(
	challenge: DemoChallenge = DEMO_CHALLENGES.age
) {
	return computeDemoChallengeCircuitHash({
		proofVersion: DEMO_PROOF_VERSION,
		templateHash: challenge.templateHash,
		responseSelector: challenge.responseSelector,
		predicate: challenge.predicate,
		proofSystem: 'toy',
	})
}

export function getDemoHiddenValueBinding(
	challenge: DemoChallenge,
	selectedValue: number
) {
	return `"${challenge.selectedValueKey}":${selectedValue}`
}

export function satisfiesDemoPredicate(
	challenge: DemoChallenge,
	response: Record<string, unknown>
) {
	const selectedValue = response[challenge.selectedValueKey]
	if(typeof selectedValue !== 'number') {
		return false
	}

	if(challenge.predicate.kind === 'age_gte') {
		return selectedValue >= challenge.predicate.threshold
	}

	if(challenge.predicate.kind === 'income_gte') {
		return selectedValue >= challenge.predicate.threshold
			&& response.currency === challenge.predicate.currency
	}

	return false
}

export function addDemoRootCertificate() {
	TLS_ADDITIONAL_ROOT_CA_LIST.push(
		readFileSync('./cert/public-cert.pem', 'utf8')
	)
}

export function makeDemoOprfOperator(): OPRFOperator {
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

export function installDemoOprfOverrides() {
	const operator = makeDemoOprfOperator()
	EXPERIMENTAL_OPRF_OPERATOR_OVERRIDES.chacha20 = operator
	EXPERIMENTAL_OPRF_OPERATOR_OVERRIDES['aes-128-ctr'] = operator
	EXPERIMENTAL_OPRF_OPERATOR_OVERRIDES['aes-256-ctr'] = operator

	return operator
}
