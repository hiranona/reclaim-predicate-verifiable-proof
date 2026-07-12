import '#src/server/utils/config-env.ts'

import { readFile } from 'fs/promises'

import {
	verifyExperimentalPredicateProofPackage,
} from '#src/providers/http/experimental-predicate-package.ts'
import {
	getArg,
	installDemoOprfOverrides,
} from '#src/scripts/experimental-predicate-demo-utils.ts'

installDemoOprfOverrides()

const packagePath = getArg(
	'package',
	'artifacts/experimental-predicate-demo/client/predicate-package.json'
)!
const artifact = JSON.parse(await readFile(packagePath, 'utf8'))
const result = await verifyExperimentalPredicateProofPackage(artifact.package)

console.log(JSON.stringify({
	role: 'third-party-verifier',
	packagePath,
	ok: result.ok,
	errors: result.errors,
	hiddenPredicate: result.hiddenPredicate,
	warning: artifact.package.warning,
	limitations: result.limitations,
}, null, 2))

if(!result.ok) {
	process.exitCode = 1
}
