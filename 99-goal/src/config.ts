import smKey from './SM_CONFIG_KEY.json';

import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
const secretsManagerClient = new SecretsManagerClient({ region: 'us-east-1' });

import fs from 'fs';

export interface AuthRequest {
  [key: string]: string | undefined

  client_id: string;
  response_type: string;
  redirect_uri: string;

  state?: string;
  nonce?: string;
  code_challenge?: string;
  code_challenge_method?: 'S256';
}

export interface TokenRequest {
  [key: string]: string | undefined

  client_id: string;
  client_secret: string;
  redirect_uri: string;
  grant_type: string;
  code: string;

  code_verifier?: string;
}

export interface Config {
  client_id: string;
  client_secret: string;
  response_type: string;
  scope: string;
  grant_type: string;

  CALLBACK_BASE_URL: string;
  CALLBACK_PATH: string;
  DISTRIBUTION?: string;
  PRIVATE_KEY: string;
  PUBLIC_KEY: string;
  DISCOVERY_DOCUMENT_URL: string;
  SESSION_DURATION: number;
  IDP_BASE_URL?: string;
  HOSTED_DOMAIN?: string;
}
const requiredKeys = [
  'client_id',
  'client_secret',
  'response_type',
  'scope',
  'grant_type',
  'CALLBACK_BASE_URL',
  'CALLBACK_PATH',
  'PRIVATE_KEY',
  'PUBLIC_KEY',
  'DISCOVERY_DOCUMENT_URL',
  'SESSION_DURATION',
];

export async function fetchConfigFromSecretsManager(): Promise<Config> {
  const secret = await secretsManagerClient.send(new GetSecretValueCommand({ SecretId: smKey.SecretsManagerKey }));
  if (secret.SecretString === undefined) throw new Error('SecretString is undefined');

  const buff = Buffer.from(JSON.parse(secret.SecretString).config, 'base64');
  const decoded = JSON.parse(buff.toString('utf-8'));

  if (!requiredKeys.every((k) => decoded.hasOwnProperty(k)))
    throw new Error(`Missing required key in config: ${requiredKeys.filter((k) => !decoded.hasOwnProperty(k))}`);

  return decoded;
}

export function fetchConfigFromFile(): Config {
  try {
    const config = JSON.parse(fs.readFileSync('./LOCAL_CONFIG.json', 'utf-8'));
    if (!requiredKeys.every((k) => config.hasOwnProperty(k)))
      throw new Error(`Missing required key in config: ${requiredKeys.filter((k) => !config.hasOwnProperty(k))}`);

    return config;
  } catch (err) {
    throw new Error(`Unable to read LOCAL_CONFIG.json: ${err}`);
  }
}
