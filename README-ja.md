# Reclaim Predicate Verifiable Proof

この fork は、Reclaim Attestor Core に「隠された値に対する述語証明」と
「第三者検証用メタデータ」を追加する実験ブランチです。

> この fork の `main` は、この実験の安定版ベースラインとして扱います。
> upstream `reclaimprotocol/attestor-core` のクリーンな mirror ではありません。

元の upstream README は [README-upstream.md](./README-upstream.md) に退避しています。
英語版は [README.md](./README.md) です。

## 今回新規に実現した機能

このブランチでは、HTTP レスポンス中の隠されたフィールドについて、値そのものを
signed claim context に入れずに predicate を検証できる実験フローを追加しています。

追加した機能:

- experimental predicate proof を TOPRF で隠された HTTP response value に束縛する。
- client が claim context に入れた `experimentalPredicateProof` を、attestor 側で検証済みの
  `hiddenPredicate` statement に変換する。
- signed statement には raw TOPRF nullifier text を入れず、`hiddenValueBindingHash` だけを入れる。
- predicate circuit hash ごとの verifier registry を追加する。
- demo challenge 用の実験 verifier adapter を追加する。
- Reclaim の claim response から第三者検証用 package を作る。
- signed `hiddenPredicate.transcriptBinding` から導出した
  `attestorObservedTranscriptCommitment` を package に含める。
- 元の `ClaimTunnelRequest.transcript` を保持している場合、replay 可能な ZK/TOPRF reveal metadata を
  package に含める。
- package の整合性、attestor claim signature、predicate proof binding、transcript binding、
  replayable reveal proof binding を検証する。

この実装は実験用です。含まれている verifier adapter は Alice age / Bob income predicate 形状を
確認する toy adapter です。本番相当にするには、実 circuit verifier と verifier artifact が必要です。

## 主なファイル

- `src/providers/http/experimental-predicate.ts`
  - HTTP provider 検証中に predicate proof を検証し、TOPRF hidden value と束縛する。
- `src/providers/http/experimental-predicate-package.ts`
  - 第三者検証用 package を作成・検証する。
- `src/providers/http/experimental-predicate-verifier.ts`
  - 実験 verifier adapter の形を定義する。
- `src/utils/zk.ts`
  - ZK reveal 検証中に TOPRF hidden value binding を記録する。
- `src/server/utils/assert-valid-claim-request.ts`
  - 検証済み predicate statement を signed claim context に移す。
- `src/client/create-claim.ts`
  - replay 可能な第三者検証 package を作るために、`ClaimTunnelRequest.transcript` を保持できる
    `onClaimRequestPrepared` hook を提供する。

## Usage: Role-Based Demo

このデモは、origin HTTPS server、Reclaim proxy/attestor、client/prover、
third-party verifier を別々の terminal command に分けて、protocol の形を見せるものです。

最初の例で示す statement は次です。

```text
https://localhost:9443/profile の JSON field $.age は age >= 20 を満たす。
raw age value は signed claim context には入れない。
```

デモ用 response body は次です。

```json
{"name":"alice","age":25,"height":170}
```

predicate verifier は toy adapter です。これは本物の range-proof 実装ではなく、
実 circuit verifier、circuit hash、verifying key、registry entry をどこに差し込むかを
示すためのものです。

この section のコマンドは、この repository root から実行します。

```bash
cd reclaim-predicate-verifiable-proof
```

### 環境

この fork の demo / test script は Node の built-in TypeScript stripping を使うため、
Node 22 以上を使ってください。Node 18 では、必要な
`node --experimental-strip-types`、`--experimental-test-module-mocks`、
`--test-force-exit` が使えません。

このブランチで確認した環境:

| Component | Version |
| --- | --- |
| OS | Ubuntu 24.04.4 LTS on WSL2 |
| Kernel | Linux 5.15.167.4-microsoft-standard-WSL2 x86_64 |
| Node.js | v22.23.1 |
| npm | 9.2.0 |

Node version を切り替えた後に tests を実行する場合は、native module を rebuild してください。

```bash
npm rebuild re2
```

### 依存関係を入れる

```bash
npm ci
```

以下のコマンドでは `.env.test` の local demo key を読むため、`NODE_ENV=test` を付けます。

### Demo Challenges

このデモには 2 つの verifier challenge が含まれています。JSON selector、predicate、
template hash、circuit hash がそれぞれ異なるため、単一の hard-coded statement だけに
閉じた flow ではないことを確認できます。

| Demo | Fixture body | Selector | Predicate | Package |
| --- | --- | --- | --- | --- |
| Demo 1: Alice age proof | `{"name":"alice","age":25,"height":170}` | `$.age` | `age >= 20` | `predicate-package.json` |
| Demo 2: Bob income proof | `{"name":"bob","annualIncome":85000,"currency":"USD","employer":"example-corp"}` | `$.annualIncome` | `annualIncome >= 50000 USD` | `predicate-package-income.json` |

どちらの場合も、verifier challenge が provider template、response selector、predicate schema、
proof system、circuit hash を固定します。client はその challenge に対応する proof を生成し、
attestor は TOPRF/ZK で束縛された hidden response segment に対して proof を検証し、
third-party verifier は同じ signed challenge identity に対して package を検証します。

ここがこの demo の汎用化のポイントです。client は repository 全体で hard-code された
単一 statement を証明しているのではありません。この demo では verifier からのお題を
`src/scripts/experimental-predicate-demo-utils.ts` の `DemoChallenge` entry として表しています。
各 challenge は、本番の predicate registry entry が将来持つべき field と同じ形を持ちます。

```ts
{
  templateHash,
  responseSelector,
  predicate,
  proofSystem,
  circuitHash
}
```

Demo 1 と Demo 2 は、同じ Reclaim/TOPRF/package plumbing を使いながら、異なる
verifier-defined statement を実行します。

```text
Alice challenge -> $.age          -> age_gte(20)              -> circuitHash A
Bob challenge   -> $.annualIncome -> income_gte(50000, "USD") -> circuitHash B
```

attestor は起動時に両方の challenge verifier を登録します。client は `--demo age` または
`--demo income` でどちらかを選び、対応する proof を作ります。third-party verifier は
`hiddenPredicate` に埋め込まれた challenge identity に対して signed package を検証します。

### Role 対応表

| Role | Command | データ境界 |
| --- | --- | --- |
| Origin HTTPS server | `npm run demo:predicate:fixture` | 選択した demo JSON を `/profile` または `/income` で返す。 |
| Proxy / Attestor | `npm run demo:predicate:attestor` | Reclaim transcript、TOPRF/ZK reveal、hidden-value binding、登録済み predicate proof を検証して claim に署名する。 |
| Client fetch step | `npm run demo:predicate:fetch` | 選択した origin JSON を読み、client が観測した入力ファイルを書き出す。 |
| Client / Prover | `npm run demo:predicate:client` | client 観測入力ファイルを読み、attestor 経由で取得し、選択した hidden predicate を証明し、第三者検証 package JSON を出力する。 |
| Third-party verifier | `npm run demo:predicate:verify` | package JSON を読み、attestor signature、claim binding、predicate proof hash、transcript binding、replayable reveal binding を検証する。 |

### Demo 1: Alice Age Proof

Demo 1 が default です。下のコマンドでは verifier challenge が見えるように `--demo age` を
明示していますが、省略しても同じ動作になります。

#### 1. Origin HTTPS Server

Terminal 1:

```bash
NODE_ENV=test npm run demo:predicate:fixture -- \
  --demo age \
  --host localhost \
  --port 9443
```

local HTTPS fixture は次で起動します。

```text
https://localhost:9443/profile
```

選択対象 field は `$.age` です。証明したい predicate は `age >= 20` です。

#### 2. Proxy / Attestor

Terminal 2:

```bash
NODE_ENV=test npm run demo:predicate:attestor -- \
  --host 127.0.0.1 \
  --port 8001 \
  --out-dir artifacts/experimental-predicate-demo/attestor
```

local Reclaim attestor は次で起動します。

```text
ws://127.0.0.1:8001/ws
```

起動時に、次の Alice age verifier を登録します。

```text
template: experimental-predicate-demo-profile-v1
selector: $.age
predicate: age >= 20
proof system: toy
```

Demo 2 で使う Bob income verifier も同時に登録します。

```text
template: experimental-predicate-demo-income-v1
selector: $.annualIncome
predicate: annualIncome >= 50000 USD
proof system: toy
```

attestor 側 demo metadata は次に書き出します。

```text
artifacts/experimental-predicate-demo/attestor/attestor-metadata.json
```

production design では、この verifier registration は、provider template、selector、
predicate schema、circuit hash、verifier artifact を対応づける共用 predicate registry に
置き換えるべきです。

#### 3a. Client Fetch Step

Terminal 3:

```bash
NODE_ENV=test npm run demo:predicate:fetch -- \
  --demo age \
  --fixture-url https://localhost:9443/profile \
  --out-file artifacts/experimental-predicate-demo/client/client-observed-profile.json
```

これは client 側の curl 相当 step です。client が predicate witness input として使う
profile body を次に書き出します。

```text
artifacts/experimental-predicate-demo/client/client-observed-profile.json
```

この step は、demo で平文改ざん確認を見やすくするためだけに分けています。これは
Reclaim claim の信頼の起点ではありません。本番 client では、この別個の curl 相当 fetch は
通常不要で、3b の attestor-mediated fetch の中で witness input を作る形が自然です。

改ざん確認をしたい場合は、3b を実行する前にこの file を編集します。たとえば
`"age": 25` を `"age": 15` に変えると、client 側の proof generation が失敗します。
`99` など別の値に変えると、predicate proof が Reclaim transcript 経由で観測された
TOPRF hidden value と一致しなくなるため、後続の attestor binding が失敗します。

#### 3b. Client / Prover

Terminal 3:

```bash
NODE_ENV=test npm run demo:predicate:client -- \
  --demo age \
  --fixture-url https://localhost:9443/profile \
  --attestor-url ws://127.0.0.1:8001/ws \
  --profile-file artifacts/experimental-predicate-demo/client/client-observed-profile.json \
  --out-dir artifacts/experimental-predicate-demo/client
```

client/prover は次を実行します。

- `client-observed-profile.json` を読み、toy `age >= 20` predicate proof input を作る。
- fixture URL を Reclaim attestor 経由で取得する。
- `$.age` を `responseRedactions: [{ jsonPath: "$.age", hash: "oprf" }]` として隠す。
- claim context に `experimentalPredicateProof` を付ける。
- prepared `ClaimTunnelRequest.transcript` を保持する。
- attestor から signed Reclaim claim を受け取る。
- 第三者検証 package を次に書き出す。

```text
artifacts/experimental-predicate-demo/client/predicate-package.json
```

このコマンドを実行するのは client/prover ですが、claim を accept/reject するのは
claim verification 中の proxy/attestor です。

signed claim context には `hiddenPredicate` が含まれます。raw hidden age value は含まれません。

#### 4. Third-Party Verifier

Terminal 4:

```bash
NODE_ENV=test npm run demo:predicate:verify -- \
  --package artifacts/experimental-predicate-demo/client/predicate-package.json
```

verifier は package file だけを読み、次を検証します。

- attestor claim signature;
- fixed IV を含む stripped request に対する attestor result signature;
- 再計算した claim identifier と signing payload hash;
- signed `hiddenPredicate.proofHash` と detached predicate proof;
- `hiddenPredicate.transcriptBinding` から導出される transcript commitment;
- signed `hiddenPredicate.transcriptBinding` に対する ciphertext hash;
- replayable reveal proof の range binding;
- signed hidden transcript range について replay した Reclaim ZK/TOPRF verification;
- independent-verification material の不足に関する warning metadata。

verifier は signed claim context から raw hidden age value を知りません。

role-based demo path では、package に hidden TLS record ciphertext、replay 可能な
`zkReveal`、fixed IV を含む stripped request への attestor result signature が入ります。
signed claim context には ciphertext hash と cipher suite が入ります。これにより
third-party verifier は、signed ciphertext hash を確認し、`verifyZkPacket(...)` を
再実行することで client 側の ciphertext / hidden witness 差し替えを検知できます。

### Demo 2: Bob Income Proof

Demo 2 は同じ role と attestor process を使いますが、別の verifier challenge を使います。

```text
https://localhost:9443/income の JSON field $.annualIncome は
annualIncome >= 50000 USD を満たす。raw income value は signed claim context には入れない。
```

Bob income fixture を起動します。

```bash
NODE_ENV=test npm run demo:predicate:fixture -- \
  --demo income \
  --host localhost \
  --port 9443
```

Demo 1 の attestor がまだ起動している場合は、そのまま再利用できます。attestor は起動時に
両方の demo verifier を登録します。次に fixture body を fetch します。

```bash
NODE_ENV=test npm run demo:predicate:fetch -- \
  --demo income \
  --fixture-url https://localhost:9443/income \
  --out-file artifacts/experimental-predicate-demo/client/client-observed-income.json
```

client/prover を実行します。

```bash
NODE_ENV=test npm run demo:predicate:client -- \
  --demo income \
  --fixture-url https://localhost:9443/income \
  --attestor-url ws://127.0.0.1:8001/ws \
  --profile-file artifacts/experimental-predicate-demo/client/client-observed-income.json \
  --package-file artifacts/experimental-predicate-demo/client/predicate-package-income.json \
  --out-dir artifacts/experimental-predicate-demo/client
```

Bob package を検証します。

```bash
NODE_ENV=test npm run demo:predicate:verify -- \
  --package artifacts/experimental-predicate-demo/client/predicate-package-income.json
```

改ざん確認をしたい場合は、client/prover を実行する前に `client-observed-income.json` を
編集します。`annualIncome` を `40000` に変えると、client 側の proof generation が失敗します。
`90000` など predicate を満たす別の値に変えると、predicate proof が Reclaim transcript 経由で
観測された TOPRF hidden value と一致しなくなるため、後続の attestor binding が失敗します。

### 別の Predicate Demo を追加する方法

別の demo を追加するには、新しい verifier challenge を定義し、同じ 4 role の流れに接続します。

1. `src/scripts/experimental-predicate-demo-utils.ts` に challenge/template を定義する:
   template id、endpoint、response selector、predicate kind と parameter、proof system、
   circuit hash derivation。
2. TOPRF/ZK redaction で束縛できる hidden field path を持つ、安定した JSON shape の fixture
   response を追加または選択する。
3. その challenge 用の client proof builder を実装する: response を parse し、hidden witness を
   抽出し、public input を作り、`hiddenValueBinding` に束縛する。
4. `src/scripts/experimental-predicate-demo-attestor.ts` で circuit hash に対応する attestor verifier を
   登録する。
5. independent verification が必要な場合は、third-party package に signed `hiddenPredicate`、
   detached predicate proof、transcript binding、ciphertext hash、replayable reveal metadata が
   入ることを確認する。
6. wrong selector、wrong template、false predicate、別 claim への stale proof 付け替え、
   ciphertext/reveal range 変更について tamper check を追加する。

production system では、この challenge object は共用 predicate registry entry になるべきです。
client、attestor、third-party verifier は、client が渡した verifier metadata を信じるのではなく、
同じ registry entry を解決するべきです。

現在の demo code は、新しい例の多くが同じ edit path で追加できるように整理しています。

| Step | File | 追加する内容 |
| --- | --- | --- |
| challenge を定義する | `src/scripts/experimental-predicate-demo-utils.ts` | `DemoName` を拡張し、endpoint、fixture body、selector、predicate、template hash、proof payload label を持つ `DEMO_CHALLENGES.<name>` entry を追加する。 |
| predicate shape を受け入れる | `src/providers/http/experimental-predicate.ts` | `ExperimentalPredicate` に predicate variant を追加し、`isSupportedTruePredicateClaim(...)` で basic public-input shape を許可する。 |
| toy proof を検証する | `src/providers/http/experimental-predicate-verifier.ts` | challenge との equality check で十分なら `makeDemoChallengeToyVerifier(...)` を再利用し、より複雑な toy proof なら専用 adapter を追加する。 |
| verifier を登録する | `src/scripts/experimental-predicate-demo-attestor.ts` | 通常の demo では変更不要。`DEMO_CHALLENGES` の全 entry を登録する。 |
| fetch/prove/verify | demo scripts | 新しい challenge が既存の JSON numeric-field shape に従い、`--demo <name>` で選択できるなら変更不要。 |
| flow を文書化する | `README-ja.md` | 新しい fixture body、selector、predicate、package path、tamper example を追加する。 |

たとえば将来 "Carol account balance" demo を足す場合、新しい attestor command や verifier command は
不要で、次のような challenge を足す形にできます。

```ts
balance: {
  endpoint: "/balance",
  templateHash: "experimental-predicate-demo-balance-v1",
  responseSelector: "$.balance",
  predicate: { kind: "balance_gte", threshold: 1000, currency: "USD" },
  defaultBody: { name: "carol", balance: 1500, currency: "USD" },
  selectedValueKey: "balance"
}
```

その場合も、同じ command shape を使えます。

```bash
NODE_ENV=test npm run demo:predicate:fixture -- --demo balance
NODE_ENV=test npm run demo:predicate:fetch -- --demo balance
NODE_ENV=test npm run demo:predicate:client -- --demo balance
NODE_ENV=test npm run demo:predicate:verify -- --package artifacts/experimental-predicate-demo/client/predicate-package-balance.json
```

新しい predicate が本物の parser circuit や別の proof system を必要とする場合でも、
`DemoChallenge` entry は verifier challenge identity を記録する場所として使えます。
その場合は、`buildDemoPredicateProof...` の裏側と登録済み verifier adapter を、
本物の proof builder と verifier artifact lookup に置き換えます。

### Regression Tests

上の role-based demo が利用者向けの入口です。fork を編集するときは、下の低レイヤーの
regression tests も有用です。

```bash
npm run run:test-files -- --test src/tests/experimental-predicate.test.ts
npm run run:test-files -- --test-name-pattern "experimental predicate" --test src/tests/claim-creation.test.ts
npm run run:test-files -- --test src/tests/http-provider-utils.test.ts
```

## フロー

```text
Client
  |
  | A. Reclaim attestor 経由で HTTPS response を取得
  | B. responseRedactions[... hash: "oprf"] で JSON field を選択
  | C. 隠した response segment について TOPRF/ZK reveal を生成
  | D. claim context に experimentalPredicateProof を付ける
  v
Attestor
  |
  | E. verifyZkPacket(...)
  |      - ZK/TOPRF reveal を検証
  |      - HiddenValueBinding を記録
  |
  | F. assertExperimentalPredicateProof(...)
  |      - selector/template/circuit/predicate result を確認
  |      - proof public input が HiddenValueBinding に束縛されているか確認
  |      - 登録済み predicate verifier を呼ぶ
  |
  | G. assertValidProviderTranscript(...)
  |      - experimentalPredicateProof を削除
  |      - hiddenPredicate を signed claim context に書く
  |
  | H. claimTunnel(...)
  |      - createSignDataForClaim(claim) に署名
  v
Signed Reclaim Claim
  |
  | I. buildExperimentalPredicateProofPackageFromClaimResponse(...)
  |      - attestor signature material を追加
  |      - transcript commitment を追加
  |      - replayable zkReveal/TOPRF metadata を必要に応じてコピー
  v
Third Party
  |
  | J. verifyExperimentalPredicateProofPackage(...)
  |       - claim signature を検証
  |       - claim identifier と signing payload hash を再計算
  |       - hiddenPredicate/proof hash を確認
  |       - transcript commitment を確認
  |       - replayable reveal proof binding を確認
  |       - ciphertext hash binding を確認
  |       - fixed IVs について attestor result signature を確認
  |       - signed hidden range について verifyZkPacket(...) を再実行
  v
Accept / Reject
```

## 改ざん検知表

| 改ざん内容 | 何で検知するか | 関数 / ファイル |
| --- | --- | --- |
| predicate proof の response selector を変える | 最初の OPRF JSON redaction との selector 照合 | `assertExperimentalPredicateProof` in `src/providers/http/experimental-predicate.ts` |
| proof selector と public input selector をずらす | public input selector の照合 | `assertExperimentalPredicateProof` |
| 別 provider template 用の proof に差し替える | public input template hash の照合 | `assertExperimentalPredicateProof` |
| circuit hash を差し替える | circuit hash の再計算 | `assertExperimentalPredicateProof` |
| 未対応 predicate または false predicate を主張する | predicate kind、threshold、result の確認 | `assertExperimentalPredicateProof` |
| TOPRF/ZK で証明されていない値に predicate proof を束縛する | HiddenValueBinding lookup | `assertExperimentalPredicateProof` |
| predicate verifier を設定しない | verifier presence check | `assertExperimentalPredicateProof` |
| predicate verifier が失敗する proof を使う | 登録済み verifier の戻り値 | `assertExperimentalPredicateProof`; registry は `src/config/index.ts` |
| signed context に raw hidden nullifier を残す | signed statement は `hiddenValueBindingHash` のみ保持 | `buildHiddenPredicateStatement` in `experimental-predicate.ts` |
| predicate proof を別の signed claim に付け替える | signed `hiddenPredicate.proofHash` と predicate proof hash の照合 | `verifyExperimentalPredicateProofPackage` in `experimental-predicate-package.ts` |
| provider、parameters、context、owner、timestamp、epoch を署名後に変える | attestor claim signature 検証 | `verifyClaimSignature` in `experimental-predicate-package.ts` |
| attestation 後に signed request の fixed IVs を変える | attestor result signature 検証 | `verifyResultSignature` in `experimental-predicate-package.ts` |
| provider、parameters、context を変えて古い identifier を残す | identifier 再計算 | `computeClaimIdentifier` in `experimental-predicate-package.ts` |
| claim signing payload description を変える | signing payload hash の照合 | `buildClaimSigningPayload` and `verifyExperimentalPredicateProofPackage` |
| package commitment 内の record number、packet offset、length、nullifier hash を変える | commitment 再計算 | `buildAttestorObservedTranscriptCommitment` and `verifyExperimentalPredicateProofPackage` |
| hidden TLS record の replay ciphertext を変える | signed ciphertext hash check、その後の `verifyZkPacket(...)` replay | `verifyReplayableRevealProof` |
| `hiddenValueBindingHash` と transcript binding の nullifier hash をずらす | hash equality check | `verifyExperimentalPredicateProofPackage` |
| attestor-observed ciphertext、result signature、signed request がないのに独立第三者検証可能と主張する | warning consistency check | `verifyReplayableRevealProof` in `experimental-predicate-package.ts` |
| replayable reveal metadata を省く | warning consistency check | `verifyReplayableRevealProof` |
| replayable reveal metadata を別 range のものに差し替える | transcript range binding check | `verifyReplayableRevealProof` |
| replayable reveal metadata を package 作成後に変える | replay proof hash check | `verifyReplayableRevealProof` |
| signed hidden transcript binding を証明しない `zkReveal` に変える | replayed ZK/TOPRF verification | `verifyReplayableZkPacket` in `experimental-predicate-package.ts` |
| toy proof の predicate result や形状を変える | verifier adapter check | `verifyDemoChallengeToyProof` / `verifyProfileAgeGte20ToyProof` in `experimental-predicate-verifier.ts` |

## 現在の制約

- predicate verifier adapter は実験用かつ toy 実装です。
- role-based demo package には、third-party verifier が signed hidden range について
  Reclaim ZK/TOPRF verification を再実行するための material が入ります。ただし、このブランチは
  toy predicate proof と demo OPRF operator を使っています。本番設計では script-local な
  demo registration ではなく、共用 registry から実 verifier artifact と OPRF/ZK operator を
  解決するべきです。
- `replayableRevealProof` を含めるには、caller が `onClaimRequestPrepared` で元の
  `ClaimTunnelRequest.transcript` を保持している必要があります。
- このブランチは production API ではなく、Reclaim 既存の TOPRF/ZK 機構で hidden predicate
  statement と第三者検証 package が実現できるかを評価する proof-of-concept です。

## 本物の Predicate Registry に向けた位置づけ

今回入っている Alice age / Bob income verifier は toy adapter です。Reclaim の flow のどこに
predicate verifier を差し込むかを示すためのもので、本番 predicate の配布モデルとしては不十分です。

本番相当にするなら、既存の
[Explore Providers](https://dev.reclaimprotocol.org/explore) / Reclaim
[Provider](./docs/provider.md) に近い形が必要です。つまり、claim template、response selector、
predicate kind、circuit artifact の対応を共用 registry が記述し、client が claim ごとに
private verifier を勝手に作るのではなく、client、attestor、third-party verifier が同じ
registry entry を解決する形です。

その registry entry には少なくとも以下が必要です。

- provider/template identifier と version;
- response selector と expected bound segment encoding;
- `age_gte` や `income_gte` などの predicate schema と許可される threshold parameter;
- proof system と circuit hash;
- verifying key または verifier artifact の場所;
- public input schema と canonicalization rule;
- artifact 自体が client-controlled にならないための registry signature、digest、allowlist metadata。

その場合の flow は次の形になります。

```text
Claim template / provider definition
  -> registry entry
  -> circuit + verifier artifact
  -> client が predicate proof を生成
  -> attestor が registry-selected verifier で proof を検証
  -> third party が同じ registry entry を解決して package を検証
```

このブランチが実装しているのは、この構成のうち binding と package verification の部分です。
共用 circuit registry や artifact distribution layer はまだ実装していません。

## テスト

このブランチで主に確認した targeted tests:

```bash
npm run run:test-files -- --test src/tests/experimental-predicate.test.ts
npm run run:test-files -- --test-name-pattern "experimental predicate" --test src/tests/claim-creation.test.ts
npm run run:test-files -- --test src/tests/http-provider-utils.test.ts
```

## ビルドに関する付記

上記の Node 22 確認環境では、この実験向けの targeted tests と `npm run build` が通っています。
別の Node version で native `re2` module を install していた場合は、tests を実行する前に
`npm rebuild re2` で rebuild してください。
