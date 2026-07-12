import '#src/server/utils/config-env.ts'

import { writeFile, mkdir } from 'fs/promises'
import https from 'https'
import path from 'path'

import {
	assertDemoProfile,
	getArg,
} from '#src/scripts/experimental-predicate-demo-utils.ts'

const fixtureUrl = getArg('fixture-url', 'https://localhost:9443/profile')!
const outDir = getArg('out-dir', 'artifacts/experimental-predicate-demo/client')!
const outFile = getArg('out-file', path.join(outDir, 'client-observed-profile.json'))!

await mkdir(path.dirname(outFile), { recursive: true })

const body = await fetchProfile(fixtureUrl)
const profile = JSON.parse(body)
assertDemoProfile(profile)

await writeFile(outFile, `${JSON.stringify(profile, null, 2)}\n`)

console.log(JSON.stringify({
	role: 'client-fetch',
	fixtureUrl,
	outFile,
	selectedField: '$.age',
	observedAge: profile.age,
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
