# lambdaedge-oidc

Lambda@Edge で OIDC 認証 (GCP で動作確認) を実現するためのサンプルコードです。全体の流れは以下を参考にしています。

- https://github.com/Widen/cloudfront-auth
- https://github.com/aws-samples/lambdaedge-openidconnect-samples

## 準備
Google Cloud の OAuth 2.0 クライアント ID で確認していますが、他でも使えるのではないかと思います。以下は Google Cloud での設定方法です。
### Google Cloud の OAuth 2.0 クライアント ID の作成
認証情報のページ https://console.cloud.google.com/apis/credentials から OAuth 2.0 クライアント ID を作成します。
- 同意画面の設定 (やってなければ)
- OAuth クライアント ID の作成
  - アプリケーションの種類: Web アプリケーション
  - 承認済みのリダイレクト URI
    - (テスト用) http://localhost:3000/_callback
    - (CloudFront 用, 後で追加でも可) https://<CloudFront のドメイン名>/_callback

クライアントID, クライアントシークレットをメモしておきます。
### 認証クッキー用のキーを作成
認証クッキーの署名、検証に使うキーペアを作成します。
たとえば https://github.com/aws-samples/lambdaedge-openidconnect-samples/blob/master/docs/keypairs.md の例のようにして作成します。

```bash
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -outform PEM -pubout -out public.pem
ls private.pem public.pem
```

### Config の作成
Lambda@Edge では環境変数が使えないので、設定情報は JSON ファイルに記述します。

`./src/.example.LOCAL_CONFIG.json` をコピーしてローカル開発用の `./src/LOCAL_CONFIG.json` を作成します。
同様に、`./src/.example.LOCAL_CONFIG.json` をコピーして CloudFront Lambda@Edge 用の `./src/CF_CONFIG.json` を作成します。

それぞれ、 `$CLIENT_ID_FROM_IDP`, `$CLIENT_SECRET_FROM_IDP`, `$CLOUDFRONT_DOMAIN`, `"PRIVATE_KEY"` の値, `"PUBLIC_KEY"` の値, `$IDP_DOMAIN` を設定します。`"SESSION_DURATION"` の値もお好みで変えてください。

#### CloudFront Lambda@Edge 用 Config
作成した `CF_CONFIG.json` をエンコードして us-east-1 の SecretsManager に保存します。

```bash
cd ./src
openssl base64 -in CF_CONFIG.json -out CF_CONFIG.json.encoded
```

AWS コンソールより us-east-1 の Secrets Manager で
- シークレットのタイプ: その他のシークレット
- キー/値
  - キー: `config`
  - 値: `CF_CONFIG.json.encoded` の内容
- シークレットの名前: 任意の名前 (このあと `SM_CONFIG_KEY.json` に記述する)

として保存します。

`./src/.example.SM_CONFIG_KEY.json` をコピーして `./src/SM_CONFIG_KEY.json` を作成します。`your-key-name` を作成したシークレットの名前で置き換えます。

#### 開発環境用 Config
開発サーバでは `./src/LOCAL_CONFIG.json` をそのまま読み込みます。

## Deploy

```bash
# プロジェクトルートで
sam build
sam deploy --guided
```

デプロイされた Lambda Function の ARN をメモし、CloudFront の Viewer Request で動作する Lambda@Edge として登録します。

## ローカル開発サーバ

```bash
cd ./src
npm run dev
```

## テスト

ToDo
