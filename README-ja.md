# Reclaim Predicate Verifiable Proof

この fork は、Reclaim Attestor Core に「隠された値に対する述語証明」と
「第三者検証用メタデータ」を追加する実験ブランチです。

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
- profile age predicate 用の実験 verifier adapter を追加する。
- Reclaim の claim response から第三者検証用 package を作る。
- signed `hiddenPredicate.transcriptBinding` から導出した
  `attestorObservedTranscriptCommitment` を package に含める。
- 元の `ClaimTunnelRequest.transcript` を保持している場合、replay 可能な ZK/TOPRF reveal metadata を
  package に含める。
- package の整合性、attestor claim signature、predicate proof binding、transcript binding、
  replayable reveal proof binding を検証する。

この実装は実験用です。含まれている verifier adapter は profile age predicate 形状を確認する
toy adapter です。本番相当にするには、実 circuit verifier と verifier artifact が必要です。

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

## フロー

```text
Client
  |
  | 1. Reclaim attestor 経由で HTTPS response を取得
  | 2. responseRedactions[... hash: "oprf"] で JSON field を選択
  | 3. 隠した response segment について TOPRF/ZK reveal を生成
  | 4. claim context に experimentalPredicateProof を付ける
  v
Attestor
  |
  | 5. verifyZkPacket(...)
  |      - ZK/TOPRF reveal を検証
  |      - HiddenValueBinding を記録
  |
  | 6. assertExperimentalPredicateProof(...)
  |      - selector/template/circuit/predicate result を確認
  |      - proof public input が HiddenValueBinding に束縛されているか確認
  |      - 登録済み predicate verifier を呼ぶ
  |
  | 7. assertValidProviderTranscript(...)
  |      - experimentalPredicateProof を削除
  |      - hiddenPredicate を signed claim context に書く
  |
  | 8. claimTunnel(...)
  |      - createSignDataForClaim(claim) に署名
  v
Signed Reclaim Claim
  |
  | 9. buildExperimentalPredicateProofPackageFromClaimResponse(...)
  |      - attestor signature material を追加
  |      - transcript commitment を追加
  |      - replayable zkReveal/TOPRF metadata を必要に応じてコピー
  v
Third Party
  |
  | 10. verifyExperimentalPredicateProofPackage(...)
  |       - claim signature を検証
  |       - claim identifier と signing payload hash を再計算
  |       - hiddenPredicate/proof hash を確認
  |       - transcript commitment を確認
  |       - replayable reveal proof binding を確認
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
| provider、parameters、context を変えて古い identifier を残す | identifier 再計算 | `computeClaimIdentifier` in `experimental-predicate-package.ts` |
| claim signing payload description を変える | signing payload hash の照合 | `buildClaimSigningPayload` and `verifyExperimentalPredicateProofPackage` |
| package commitment 内の record number、packet offset、length、nullifier hash を変える | commitment 再計算 | `buildAttestorObservedTranscriptCommitment` and `verifyExperimentalPredicateProofPackage` |
| `hiddenValueBindingHash` と transcript binding の nullifier hash をずらす | hash equality check | `verifyExperimentalPredicateProofPackage` |
| replayable reveal metadata がないのに独立第三者検証可能と主張する | warning consistency check | `verifyReplayableRevealProof` in `experimental-predicate-package.ts` |
| replayable reveal metadata を別 range のものに差し替える | transcript range binding check | `verifyReplayableRevealProof` |
| replayable reveal metadata を package 作成後に変える | replay proof hash check | `verifyReplayableRevealProof` |
| toy proof の predicate result や形状を変える | verifier adapter check | `verifyProfileAgeGte20ToyProof` in `experimental-predicate-verifier.ts` |

## 現在の制約

- predicate verifier adapter は実験用かつ toy 実装です。
- third-party package verifier は replayable reveal metadata の束縛を確認しますが、それ単体では
  full ZK verifier を再実行しません。完全に replay したい caller は、package 内の `zkReveal` と
  元 TLS record material を Reclaim 既存の `verifyZkPacket(...)` path に渡す必要があります。
- `replayableRevealProof` を含めるには、caller が `onClaimRequestPrepared` で元の
  `ClaimTunnelRequest.transcript` を保持している必要があります。
- このブランチは production API ではなく、Reclaim 既存の TOPRF/ZK 機構で hidden predicate
  statement と第三者検証 package が実現できるかを評価する proof-of-concept です。

## テスト

このブランチで主に確認した targeted tests:

```bash
npm run run:test-files -- --test src/tests/experimental-predicate.test.ts
npm run run:test-files -- --test-name-pattern "experimental predicate" --test src/tests/claim-creation.test.ts
npm run run:test-files -- --test src/tests/http-provider-utils.test.ts
```

