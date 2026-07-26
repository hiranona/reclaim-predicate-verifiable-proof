import '#src/server/utils/config-env.ts'

import { setCryptoImplementation } from '@reclaimprotocol/tls'
import { webcryptoCrypto } from '@reclaimprotocol/tls/webcrypto'
import { mkdir, readFile, writeFile } from 'fs/promises'
import https from 'https'
import path from 'path'

import { AttestorClient, createClaimOnAttestor } from '#src/client/index.ts'
import type { ClaimTunnelRequest } from '#src/proto/api.ts'
import {
	buildExperimentalPredicateProofPackageFromClaimResponse,
} from '#src/providers/http/experimental-predicate-package.ts'
import { providers } from '#src/providers/index.ts'
import {
	addDemoRootCertificate,
	assertDemoResponse,
	buildDemoPredicateProofForChallenge,
	getArg,
	getDemoChallenge,
	installDemoOprfOverrides,
} from '#src/scripts/experimental-predicate-demo-utils.ts'
import { getEnvVariable } from '#src/utils/env.ts'
import { logger } from '#src/utils/index.ts'

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
const observedResponseFile = getArg(
	'observed-response-file',
	path.join(outDir, challenge.outputFileName)
)!
const predicateInputFile = getArg(
	'predicate-input-file',
	getArg('profile-file', observedResponseFile)
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
await mkdir(path.dirname(observedResponseFile), { recursive: true })

const observedResponse = await fetchDemoResponse(fixtureUrl)
assertDemoResponse(challenge, observedResponse)
await writeFile(
	observedResponseFile,
	`${JSON.stringify(observedResponse, null, 2)}\n`
)

const predicateInput = JSON.parse(await readFile(predicateInputFile, 'utf8'))
assertDemoResponse(challenge, predicateInput)
const proof = buildDemoPredicateProofForChallenge(challenge, predicateInput)
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
			observedResponseFile,
			predicateInputFile,
			responseSelector: challenge.responseSelector,
			predicate: challenge.predicate,
			observedValue: observedResponse[challenge.selectedValueKey],
			predicateInputValue: predicateInput[challenge.selectedValueKey],
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

function fetchDemoResponse(url: string) {
	return new Promise<Record<string, unknown>>((resolve, reject) => {
		https.get(
			url,
			{ rejectUnauthorized: false },
			res => {
				const chunks: Buffer[] = []
				res.on('data', chunk => chunks.push(chunk))
				res.on('end', () => {
					const responseBody = Buffer.concat(chunks).toString('utf8')
					if(res.statusCode !== 200) {
						reject(new Error(`fixture returned HTTP ${res.statusCode}: ${responseBody}`))
						return
					}

					try {
						resolve(JSON.parse(responseBody))
					} catch(err) {
						reject(err)
					}
				})
			}
		).on('error', reject)
	})
}
