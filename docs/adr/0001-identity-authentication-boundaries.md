# ADR-0001: iHATのユーザー・端末認証境界

- 状態: Accepted
- 決定日: 2026-08-03
- 対象: iHAT、NERP、Hibee、Crowsi、Zixcel、Coela

## 文脈

一般ユーザーには通常の会員制サービスと同じログイン、セキュリティ、端末管理UIを
提供する。一方、ユーザー認証、サービス固有権限、端末sender proof、高リスク操作の
認可、Provider credential custodyを同じコンポーネントへ集約してはならない。

## 決定

`https://id.ihat.online`を唯一のiHAT OIDC issuerとする。初期OIDC Server候補は
セルフホストZITADELとし、製品実装やPostgreSQL配備は本契約Repositoryの責務外とする。
Relying PartyはAuthorization Code FlowとPKCE S256を使い、WebではBFF、Desktopでは
system browserと固定loopback callbackを使う。Implicit Grantとpassword grantは使わない。

責務は次のように分離する。

| 所有者 | 正本と責務 | 保持してはならないもの |
| --- | --- | --- |
| iHAT Identity | OIDC認証、外部IdP link、Authenticator、recovery、全体失効 | NERP/Hibeeのrole、顧客payload |
| NERP/Hibee | pairwise `sub`に対応するService Account、role、entitlement、service session | 上流token、OTP seed、他ServiceのDB |
| Local Device Agent | Device key生成、challengeへのsender proof | ユーザーpassword、OIDC Server管理鍵 |
| Credential Broker | token、Device秘密鍵、credential revisionと失効 | 顧客データ、role判断 |
| Crowsi PA | 検証済みEvidence、operation digest、一回利用Grant、replay ledger | raw OIDC token、Authenticator secret |
| Coela | 運用Projectionと明示的な管理操作 | 認証Authority、CA鍵、Credential本文 |
| Zixcel | 許可済みProvider操作へのCredential注入 | iHAT Subject graph、ブラウザ向けtoken |

ZITADELの認証状態は専用PostgreSQL、NERPとHibeeのサービス状態は互いに独立した
SQLite、秘密値はCredential Brokerに置く。DB間joinや共有テーブルを作らない。

## Identity規則

- SubjectはIdentity内部IDであり、Serviceへ配布しない。
- 各Relying Partyには異なるpairwise subjectを発行する。
- メール、UPN、表示名、電話番号を認可キーまたは自動linkキーにしない。
- Account linkは既存iHAT sessionのfresh authenticationと、新Providerの認証を両方要求する。
- Service Account、Device、Session、Authenticatorは独立して失効できる。
- Device認証はユーザー認証を、Workload認証はDevice認証を代替しない。
- `localhost`、UID、process名、端末名だけをDevice/Workload証明として受け入れない。

## 認証強度

| 方法 | 契約上の強度 | 用途 |
| --- | --- | --- |
| TOTP、Authenticator push | `baseline` | 通常ログイン、復旧前の補助Evidence |
| Passkey、FIDO2 security key | `phishing-resistant` | 通常ログイン、高リスクstep-up |
| 検証済みhardware-bound key | `hardware-bound` | 明示Policyが要求する管理操作 |

TOTPやpushのみから`phishing-resistant`を生成してはならない。高リスク操作ではfreshな
Passkey/FIDO2、Service Account、Device、Workload、proof key、正確なoperation digestを
同じ短命Evidenceへ束縛する。

## 通常フロー

1. Serviceがランダムな`state`、`nonce`、PKCE verifierを生成する。
2. system browserまたはBFFからiHATへ遷移する。
3. iHATがAuthenticatorを検証し、固定redirect URIへ一回利用codeを返す。
4. Serviceはissuer、audience、nonce、時刻、pairwise subjectを検証する。
5. tokenはBrokerへ隔離し、Serviceはopaque referenceとHttpOnly sessionだけを持つ。
6. 初回端末登録ではDevice Agentが鍵を生成し、公開鍵thumbprintだけを登録する。

高リスク操作では通常sessionをそのまま認可に使わず、operation digestを提示して再認証し、
`StepUpEvidence`をCrowsiの検証済みidentity contextへ変換する。変換先の公開Contract URIは
`crowsi://control/verified-identity-context/v1`であり、本RepositoryはCrowsiを直接参照しない。

## 障害時の判断

OIDCまたは失効freshnessを確認できない場合、既存の低リスクread sessionはServiceの
明示Policy期間内だけ継続できる。外部write、権限変更、Credential変更、全端末logout、
証明書操作、隔離解除はfail closedとする。Localな失効、緊急隔離、証拠保全は継続する。

## 結果

ユーザーUIはログイン、アカウント、Authenticator、端末、logoutへ限定できる。
OIDC ServerやProviderを交換しても9つのversioned contractは維持できる。一方、ZITADEL、
Entra、Credential Broker、各Service adapterの実装と本番ceremonyは後続Milestoneが必要で、
本ADRだけでは接続済みまたはproduction-readyを意味しない。

