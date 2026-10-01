# Security policy

このRepositoryは公開Contractとsynthetic exampleだけを保持します。token、cookie、OTP seed、
private key、recovery code、raw WebAuthn assertion、実在ユーザーの識別子を追加しないでください。

脆弱性報告には影響するschema URI、再現用のsynthetic record、期待するfail-closed結果を含め、
credentialや実データは含めないでください。未知fieldの受理、issuer/audience混同、digest不一致の
受理、step-up replay、弱いMFAの強度昇格、pairwise subjectのcross-Service再利用はSecurity
defectとして扱います。

Schema成功だけでは署名、key custody、trusted time、revocation freshness、durable replayを
証明しません。Consumerは`docs/contract-verification.md`のcontext検証も実装してください。
