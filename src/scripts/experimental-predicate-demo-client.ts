import '#src/server/utils/config-env.ts'

import { mkdir, readFile, writeFile } from 'fs/promises'
import path from 'path'

import { setCryptoImplementation } from '@reclaimprotocol/tls'
import { webcryptoCrypto } from '@reclaimprotocol/tls/webcrypto'

import { AttestorClient, createClaimOnAttestor } from '#src/client/index.ts'
import {
	buildExperimentalPredicateProofPackageFromClaimResponse,
} from '#src/providers/http/experimental-predicate-package.ts'
import type { ClaimTunnelRequest } from '#src/proto/api.ts'
import {
	addDemoRootCertificate,
	assertDemoResponse,
	buildDemoPredicateProofForChallenge,
	getArg,
	getDemoChallenge,
	installDemoOprfOverrides,
} from '#src/scripts/experimental-predicate-demo-utils.ts'
import { providers } from '#src/providers/index.ts'
import { logger } from '#src/utils/index.ts'
import { getEnvVariable } from '#src/utils/env.ts'

setCryptoImplementation(webcryptoCrypto)
addDemoRootCertificate()
const oprfOperator = installDemoOprfOverrides()

const challenge = getDemoChallenge()
const fixtureUrl = getArg(
	'fixture-url',
	`https://localhost:9443${challenge.endpoint}`
)!
const attestorUrl = getArg('attestor-url', 'ws://127.0.0.1:8001/ws')!
const outDir = getArg('out-dir', 'artifacts/experimental-predicate-demo/client')!
const profileFile = getArg(
	'profile-file',
	path.join(outDir, challenge.outputFileName)
)!
const packageFile = getArg(
	'package-file',
	path.join(
		outDir,
		challenge.name === 'age'
			? 'predicate-package.json'
			: `predicate-package-${challenge.name}.json`
	)
)!
const ownerPrivateKey = getEnvVariable('PRIVATE_KEY_HEX')
	|| '0x0123788edad59d7c013cdc85e4372f350f828e2cec62d9a2de4560e69aec7f89'

providers.http.additionalClientOptions = {
	verifyServerCertificate: false,
}

await mkdir(outDir, { recursive: true })

const responseBody = JSON.parse(await readFile(profileFile, 'utf8'))
assertDemoResponse(challenge, responseBody)
const proof = buildDemoPredicateProofForChallenge(challenge, responseBody)
let preparedRequest: ClaimTunnelRequest | undefined
const client = new AttestorClient({
	url: attestorUrl,
	logger: logger.child({ role: 'experimental-predicate-demo-client' }),
})
await client.waitForInit()

try {
	const response = await createClaimOnAttestor({
		name: 'http',
		params: {
			url: fixtureUrl,
			method: 'GET',
			responseRedactions: [
				{
					jsonPath: challenge.responseSelector,
					hash: 'oprf',
				},
			],
			responseMatches: [
				{
					type: 'contains',
					value: '',
				},
			],
		},
		secretParams: {
			authorisationHeader: 'Bearer demo',
		},
		context: {
			experimentalPredicateProof: proof,
		},
		ownerPrivateKey,
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

	if(!response.claim) {
		throw new Error(`claim creation failed: ${response.error?.message || 'missing claim'}`)
	}

	const pkg = buildExperimentalPredicateProofPackageFromClaimResponse(
		response,
		proof.proof,
		undefined,
		preparedRequest?.transcript
	)
	const artifact = {
		role: 'client-prover-output',
		demo: challenge.name,
		inputs: {
			fixtureUrl,
			attestorUrl,
			profileFile,
			responseSelector: challenge.responseSelector,
			predicate: challenge.predicate,
			observedValue: responseBody[challenge.selectedValueKey],
		},
		claim: response.claim,
		signatures: {
			attestorAddress: response.signatures?.attestorAddress,
			claimSignatureHex: response.signatures?.claimSignature
				? Buffer.from(response.signatures.claimSignature).toString('hex')
				: undefined,
		},
		predicateProof: proof.proof,
		package: pkg,
	}
	const artifactPath = packageFile
	await writeFile(artifactPath, JSON.stringify(artifact, null, 2))

	console.log(JSON.stringify({
		role: 'client-prover',
		demo: challenge.name,
		artifactPath,
		claimIdentifier: response.claim.identifier,
		hiddenPredicate: JSON.parse(response.claim.context).hiddenPredicate,
	}, null, 2))
} finally {
	await client.terminateConnection()
}
