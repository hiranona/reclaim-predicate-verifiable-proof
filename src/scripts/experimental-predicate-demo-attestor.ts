import '#src/server/utils/config-env.ts'

import { mkdir, writeFile } from 'fs/promises'
import path from 'path'

import { setCryptoImplementation } from '@reclaimprotocol/tls'
import { webcryptoCrypto } from '@reclaimprotocol/tls/webcrypto'

import { EXPERIMENTAL_PREDICATE_PROOF_VERIFIERS, WS_PATHNAME } from '#src/config/index.ts'
import { makeDemoChallengeToyVerifier } from '#src/providers/http/experimental-predicate-verifier.ts'
import {
	DEMO_CHALLENGES,
	addDemoRootCertificate,
	getArg,
	installDemoOprfOverrides,
} from '#src/scripts/experimental-predicate-demo-utils.ts'
import { createServer } from '#src/server/index.ts'

setCryptoImplementation(webcryptoCrypto)
addDemoRootCertificate()
installDemoOprfOverrides()

const host = getArg('host', '127.0.0.1')!
const port = Number(getArg('port', '8001'))
const outDir = getArg('out-dir', 'artifacts/experimental-predicate-demo/attestor')!
const registeredPredicateVerifiers = Object.values(DEMO_CHALLENGES)
	.map(challenge => {
		const verifier = makeDemoChallengeToyVerifier({
			templateHash: challenge.templateHash,
			responseSelector: challenge.responseSelector,
			predicate: challenge.predicate,
			proofSystem: 'toy',
		})
		EXPERIMENTAL_PREDICATE_PROOF_VERIFIERS.set(
			verifier.circuitHash,
			verifier.verify
		)
		return {
			demo: challenge.name,
			templateHash: challenge.templateHash,
			responseSelector: challenge.responseSelector,
			predicate: challenge.predicate,
			circuitHash: verifier.circuitHash,
			proofSystem: 'toy',
		}
	})

await createServer(port, host)

const metadata = {
	role: 'proxy-attestor',
	url: `ws://${host}:${port}${WS_PATHNAME}`,
	registeredPredicateVerifiers,
}

await mkdir(outDir, { recursive: true })
await writeFile(
	path.join(outDir, 'attestor-metadata.json'),
	`${JSON.stringify(metadata, null, 2)}\n`
)

console.log(JSON.stringify({
	...metadata,
	metadataPath: path.join(outDir, 'attestor-metadata.json'),
}, null, 2))
