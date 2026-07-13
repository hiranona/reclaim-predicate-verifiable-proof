import '#src/server/utils/config-env.ts'

import { writeFile, mkdir } from 'fs/promises'
import https from 'https'
import path from 'path'

import {
	assertDemoResponse,
	getArg,
	getDemoChallenge,
} from '#src/scripts/experimental-predicate-demo-utils.ts'

const challenge = getDemoChallenge()
const fixtureUrl = getArg(
	'fixture-url',
	`https://localhost:9443${challenge.endpoint}`
)!
const outDir = getArg('out-dir', 'artifacts/experimental-predicate-demo/client')!
const outFile = getArg(
	'out-file',
	path.join(outDir, challenge.outputFileName)
)!

await mkdir(path.dirname(outFile), { recursive: true })

const body = await fetchProfile(fixtureUrl)
const response = JSON.parse(body)
assertDemoResponse(challenge, response)

await writeFile(outFile, `${JSON.stringify(response, null, 2)}\n`)

console.log(JSON.stringify({
	role: 'client-fetch',
	demo: challenge.name,
	fixtureUrl,
	outFile,
	selectedField: challenge.responseSelector,
	observedValue: response[challenge.selectedValueKey],
}, null, 2))

function fetchProfile(url: string) {
	return new Promise<string>((resolve, reject) => {
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

					resolve(responseBody)
				})
			}
		).on('error', reject)
	})
}
