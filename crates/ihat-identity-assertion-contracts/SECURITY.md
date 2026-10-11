# Security

- Assertionは認証セッションでもbearer credentialでもありません。
- Consumerは`decode_assertion_strict`と`verify_assertion_at`を順に使い、独自JSON decodeや
  署名のみの検査をしません。
- `AssertionVerifier`実装はkey IDを固定trust storeへ解決し、ネットワーク探索やTOFUを
  行いません。
- assertionのpairwise subjectからglobal accountを逆引きしません。
- 端末proof keyの秘密値はiHATにもassertionにも保存しません。
- Consumerは`CurrentDeviceStatusV1`を独立status鍵で検証し、assertionとのexact bindingと
  one-use nonceを確認します。30秒以内でもcurrent statusを取得できない場合はfail closedします。
- Device AのstatusやepochはDevice Bへ代用できません。re-signedされた新epochは正当なstatusでも
  古いassertionとのbindingに失敗します。
- Authority wireのevidenceはcommand digest、role、proof ID、key ID、時刻へexact bindします。
  FreshUvはservice/pairwise/device/session、challenge/attempt、operation digest、4 epoch、Crowsiが
  独立算出するopaque account bindingへexact bindし、iHATへCrowsi owner refを渡しません。
- Response consumerはrequest ID、command type/digest、最小config generation、response key、時刻を
  全て検証します。unknown outcomeを成功に推測せず、同じoriginal digestのreconcileだけを使います。
- Current identity evidence要求はraw account/session locatorを運びません。authorityは端末ごとの
  durable slotをexact readし、sender fingerprintからlatest sessionを推測しません。要求TTLは
  `1..=30`秒で、assertion、current status、authority responseの期限も要求期限を越えません。
- Identity session確立は`Absent | Present { session_ref, session_epoch }`のclosed CASです。
  `Absent`再実行、stale `Present`、unknown/trailing fieldを拒否し、通常のsession発行はslotを更新しません。
