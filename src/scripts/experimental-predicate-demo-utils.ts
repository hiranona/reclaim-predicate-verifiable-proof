import { createHash } from 'crypto'
import { readFileSync } from 'fs'

import type { OPRFOperator } from '@reclaimprotocol/zk-symmetric-crypto'

import type { ExperimentalPredicateProof } from '#src/providers/http/experimental-predicate.ts'
import { EXPERIMENTAL_OPRF_OPERATOR_OVERRIDES } from '#src/utils/index.ts'

export const DEMO_TEMPLATE_HASH = 'experimental-predicate-demo-profile-v1'
export const DEMO_RESPONSE_SELECTOR = '$.age'
export const DEMO_PREDICATE = {
	kind: 'age_gte' as const,
	threshold: 20,
}

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
	if(profile.age < DEMO_PREDICATE.threshold) {
		throw new Error(
			`profile does not satisfy predicate: age ${profile.age} < ${DEMO_PREDICATE.threshold}`
		)
	}

	const proof: ExperimentalPredicateProof = {
		version: 'tlsn-mpc-lab.profile-age-predicate.v1',
		providerTemplateHash: DEMO_TEMPLATE_HASH,
		responseSelector: DEMO_RESPONSE_SELECTOR,
		predicate: DEMO_PREDICATE,
		publicInput: {
			providerTemplateHash: DEMO_TEMPLATE_HASH,
			responseSelector: DEMO_RESPONSE_SELECTOR,
			hiddenValueBinding: `"age":${profile.age}`,
			circuitHash: '',
			predicateResult: true,
		},
		proof: {
			system: 'toy',
			payload: {
				demo: 'profile-age-gte-20',
			},
		},
	}
	proof.publicInput.circuitHash = computeDemoCircuitHash()

	return proof
}

export function computeDemoCircuitHash() {
	return createHash('sha256')
		.update(JSON.stringify({
			version: 'tlsn-mpc-lab.profile-age-predicate.v1',
			providerTemplateHash: DEMO_TEMPLATE_HASH,
			responseSelector: DEMO_RESPONSE_SELECTOR,
			predicate: DEMO_PREDICATE,
		}))
		.digest('hex')
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
