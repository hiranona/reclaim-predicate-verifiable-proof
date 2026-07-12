import '#src/server/utils/config-env.ts'

import { readFileSync } from 'fs'
import { createServer } from 'https'

import { getArg } from '#src/scripts/experimental-predicate-demo-utils.ts'

const host = getArg('host', 'localhost')!
const port = Number(getArg('port', '9443'))
const age = Number(getArg('age', '25'))

if(!Number.isInteger(age) || age < 0 || age > 120) {
	throw new Error(`age must be an integer in [0, 120], got ${age}`)
}

const profile = {
	name: 'alice',
	age,
	height: 170,
}
const body = JSON.stringify(profile)

const server = createServer(
	{
		key: readFileSync('./cert/private-key.pem'),
		cert: readFileSync('./cert/public-cert.pem'),
	},
	(req, res) => {
		if(req.method !== 'GET' || req.url !== '/profile') {
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
		url: `https://${host}:${port}/profile`,
		body,
		selectedField: '$.age',
		predicate: 'age >= 20',
	}, null, 2))
})
