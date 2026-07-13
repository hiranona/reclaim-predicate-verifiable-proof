import '#src/server/utils/config-env.ts'

import { readFileSync } from 'fs'
import { createServer } from 'https'

import {
	getArg,
	getDemoChallenge,
} from '#src/scripts/experimental-predicate-demo-utils.ts'

const host = getArg('host', 'localhost')!
const port = Number(getArg('port', '9443'))
const challenge = getDemoChallenge()
const selectedValueArg = getArg('value')
const selectedValue = selectedValueArg === undefined
	? undefined
	: Number(selectedValueArg)

if(selectedValue !== undefined && !Number.isInteger(selectedValue)) {
	throw new Error(`value must be an integer, got ${selectedValueArg}`)
}

const bodyObject = {
	...challenge.defaultBody,
	...(selectedValue === undefined
		? {}
		: { [challenge.selectedValueKey]: selectedValue }),
}
const body = JSON.stringify(bodyObject)

const server = createServer(
	{
		key: readFileSync('./cert/private-key.pem'),
		cert: readFileSync('./cert/public-cert.pem'),
	},
	(req, res) => {
		if(req.method !== 'GET' || req.url !== challenge.endpoint) {
			res.writeHead(404, { 'Content-Type': 'application/json' })
			res.end(JSON.stringify({ error: 'not found' }))
			return
		}

		res.writeHead(200, {
			'Content-Type': 'application/json',
			'Content-Length': String(Buffer.byteLength(body)),
		})
		res.end(body)
	}
)

server.listen(port, host, () => {
	console.log(JSON.stringify({
		role: 'origin-server',
		demo: challenge.name,
		url: `https://${host}:${port}${challenge.endpoint}`,
		body,
		selectedField: challenge.responseSelector,
		predicate: challenge.statement,
	}, null, 2))
})
