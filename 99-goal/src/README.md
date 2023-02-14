# oidc-study-lambdaedge
ToDo

## Create Configuration

ToDo

    openssl base64 -in MYCONFIG.json -out MYCONFIG.json.encoded

Copy the contents of `MYCONFIG.json.encoded` and move on to the next step of updating the AWS Secrets Manager OIDC Secret.

## Update AWS Secrets Manager

ToDo

- Store the contents of `MYCONFIG.json.encoded` to SecretsManager in N. Virginia as:
  - Secret Key: `config`
  - Secret Value: (the encoded strings)

This "Secret name" should be specified the value in `SM_CONFIG_KEY.json`.
