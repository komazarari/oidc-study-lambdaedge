import { CloudFrontRequest, CloudFrontRequestResult, CloudFrontHeaders, CloudFrontResultResponse } from 'aws-lambda';

import { Config, fetchConfigFromSecretsManager, fetchConfigFromFile, AuthRequest } from './config';
import Axios from 'axios';
import Cookie from 'cookie';
import JsonWebToken, { JwtPayload } from 'jsonwebtoken';
import JwkToPem from 'jwk-to-pem';
import QueryString, { ParsedUrlQuery } from 'querystring';
import assert from 'assert';


export interface AuthenticationResult {
  authenticated: boolean;
  response: CloudFrontRequestResult;
}

const global = {
  isDevelop: process.env.IS_DEVELOP as string | undefined,
  config: null as Config | null,
  discoveryDocumnet: null as DiscoveryDocument | null,
}

export async function authenticate(request: CloudFrontRequest): Promise<AuthenticationResult> {
  try {
    await prepareGlobals();
    return doAuth(request);
  } catch (err) {
    console.error(err);
    return { authenticated: false, response: internalServerErrorResponse() };
  }
}

async function doAuth(request: CloudFrontRequest): Promise<AuthenticationResult> {
  assert(global.config !== null);
  const { headers, querystring } = request;
  const queryString = QueryString.parse(querystring);

  if (request.uri.startsWith(global.config.CALLBACK_PATH)) {
    return handleCallback(request, queryString);
  }

  const authTokenCookieValue = getCookieValue(headers, 'TOKEN');
  if (!authTokenCookieValue) {
    return { authenticated: false, response: oidcRedirectResponse(request) };
  }

  const [err, verifyOk] = await verifyToken(authTokenCookieValue);
  if (err) {
    switch (err.name) {
      default:
        // ToDo
        return { authenticated: false, response: internalServerErrorResponse() };
    }
  }

  assert(verifyOk);
  return { authenticated: true, response: null };
}

async function handleCallback(request: CloudFrontRequest, queryString: ParsedUrlQuery): Promise<AuthenticationResult> {
  assert(global.config !== null && global.discoveryDocumnet !== null);
  const config = global.config;
  try {
    const tokenRequest = {
      client_id: config.client_id,
      client_secret: config.client_secret,
      grant_type: config.grant_type,
      redirect_uri: `${config.CALLBACK_BASE_URL}${config.CALLBACK_PATH}`,
      code: queryString.code,
    }

    const idToken = await IdToken.get(global.discoveryDocumnet.token_endpoint, tokenRequest);
    const rawPem = tmpJwks.keys.find((key) => key.kid === idToken.decoded.header.kid); // ToDo jwks
    if (rawPem === undefined) {
      throw new Error('unable to find expected pem in JWKs keys');
    }
    const pem = JwkToPem(rawPem);
    try {
      const decoded = await verifyJwt(idToken.raw, pem, { algorithms: ['RS256'] })
      // ToDo validate NONCE
      return { authenticated: false, response: originalPathRedirectResponse(request, queryString) };
    } catch (err: unknown) {
      if (!err || !(err instanceof Error) || err.name === undefined) {
        console.error('verifyJwt failed with unknown error');
        return { authenticated: false, response: internalServerErrorResponse() };
      }
      switch (err.name) {
        case 'TokenExpiredError':
          console.log('token expired', err);
          return { authenticated: false, response: oidcRedirectResponse(request) };
        //case: 'JsonWebTokenError':
        // ToDo
        default:
          console.error('Unknown JWT error', err);
          return { authenticated: false, response: internalServerErrorResponse() }; // ToDo
      }
    }
  } catch (err) {
    console.error(err);
    return { authenticated: false, response: internalServerErrorResponse() };
  }
}

async function verifyToken(authToken: string): Promise<[Error | null, boolean]> {
  console.log('ToDo: verifyToken');
  return [null, true];
}

// --------------------
// global variables
// --------------------
async function prepareGlobals() {
  await setConfig();
  await setDiscoveryDocument();
}

async function setConfig(): Promise<void> {
  if (global.config !== null) return;

  if (global.isDevelop) {
    global.config = fetchConfigFromFile();
  } else {
    global.config = await fetchConfigFromSecretsManager();
  }
  console.log('config fetched');
}

async function setDiscoveryDocument(): Promise<void> {
  if (global.discoveryDocumnet !== null) return;
  const config = global.config as Config;
  global.discoveryDocumnet = (await Axios.get(config.DISCOVERY_DOCUMENT_URL)).data as DiscoveryDocument;
  console.log('discovery document fetched');
}

// --------------------
// response functions
// --------------------
function internalServerErrorResponse(): CloudFrontRequestResult {
  return {
    status: '500',
    statusDescription: 'Internal Server Error',
    body: 'Internal Server Error',
  };
}

function oidcRedirectResponse(request: CloudFrontRequest): CloudFrontRequestResult {
  assert(global.config !== null && global.discoveryDocumnet !== null);
  const config = global.config;
  const authRequest = {
    client_id: config.client_id,
    response_type: config.response_type,
    scope: config.scope,
    redirect_uri: `${config.CALLBACK_BASE_URL}${config.CALLBACK_PATH}`,
    state: request.uri
  };

  const response = {
    status: '302',
    statusDescription: 'Found',
    body: 'Redirecting...',
    headers: {
      location: [{
        key: 'Location',
        value: `${global.discoveryDocumnet.authorization_endpoint}?${QueryString.stringify(authRequest)}`,
      }],
      // ToDo set cookie TOKEN empty
    }
  };
  return response;
}

function originalPathRedirectResponse(request: CloudFrontRequest, queryString: ParsedUrlQuery): CloudFrontResultResponse {
  const response: CloudFrontResultResponse = {
    status: '302',
    statusDescription: 'Found',
    body: 'Back to original path',
    headers: {
      location: [
        {
          key: 'Location',
          value: queryString.state ? queryString.state.toString() : '/',
        }
      ],
      'set-cookie': [
        {
          key: 'Set-Cookie',
          value: Cookie.serialize('TOKEN',
            'dummy',
            {
              httpOnly: true,
              path: '/',
              maxAge: 60,
            })
        }
      ]
    }
  };
  return response;
}

// --------------------
// utils
// --------------------
async function verifyJwt(token: string, pem: any, options: any): Promise<JwtPayload | Error> { // ToDo: type
  return new Promise((resolve, reject) => {
    JsonWebToken.verify(token, pem, options, (err, decoded) => {
      if (err) {
        reject(err);
      } else {
        resolve(decoded as JwtPayload);
      }
    })
  });
}

function getCookieValue(headers: CloudFrontHeaders, cookieName: string): string | null {
  const cookieHeader = headers.cookie || headers.Cookie;
  if (cookieHeader === undefined || cookieHeader === null) {
    return null;
  }
  const cookies = Cookie.parse(cookieHeader[0].value);
  return cookies[cookieName];
}


// --------------------
// id token
// --------------------
class IdToken {
  constructor(
    public readonly raw: string,
    public readonly decoded: any,
  ) {
  }

  static async get(endPoint: string, tokenRequest: any) { // ToDo: type
    const tokenResponse = await Axios.post(endPoint, QueryString.stringify(tokenRequest));
    const idToken = tokenResponse.data.id_token;
    const decoded = JsonWebToken.decode(idToken, { complete: true });
    return new IdToken(idToken, decoded);
  }
}

// --------------------
// discovery document
// --------------------
interface DiscoveryDocumentBase {
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
}

type DiscoveryDocument = DiscoveryDocumentBase & Record<string, unknown>;

// --------------------
// tmp
// --------------------
function dummyAuthenticate(_request: CloudFrontRequest): AuthenticationResult {
  if (Math.random() >= 0.5) {
    return { authenticated: true, response: null };
  } else {
    return {
      authenticated: false,
      response: {
        status: '401',
        statusDescription: 'Unauthorized',
        body: 'Unauthorized',
      },
    };
  }
}

// https://www.googleapis.com/oauth2/v3/certs
const tmpJwks = {
  "keys": [
    {
      "kid": "b49c5062d890f5ce449e890c88e8dd98c4fee0ab",
      "n": "zSkYGlwDMKd7TWEuog27TdT04nLqocBhSKc6XpEfojywqKTACMtwzA3jtSC0pCTtf2a6VVOPZdMEmWYA32aqymUWmxCwLK12_R_s4WE8aRjzPzm9dx1P-3JA2286EF39jSq1btIhZbx_Q791heUFbsCMf1B9l3GODjMXFx4Hopuu7SnUffDGehdMQrphd2kNmzOfJ7DxTTwmtYwqnBjFwCI8vYRf72aNwAZ4xwwb7j4dUUCz19_EAa4TyqbGvSy4L1-kix6wTtXIwnUGH_dxFFCqa7WATsQ-KXBaFkXh7Px69M1KabItapQibNWQhMyeKxfRVNEih0C3NYLN6ZGkWQ",
      "use": "sig",
      "e": "AQAB",
      "alg": "RS256",
      "kty": "RSA" as 'RSA'
    },
    {
      "e": "AQAB",
      "kid": "5962e7a059c7f5c0c0d56cbad51fe64ceeca67c6",
      "n": "lHW8Q4I2Qcz1PdtkiCBeeoZHTdjrw8c9sqGODztqaEvggSBl-wcBnLisXIulEkwtCvEwdx4VW4173yi5LLFc47Z1J6-1z9O0xaja7FQNG5xkSYtjOxJyPY7sqDnt9mcoMZEcBf_XB0Uc6Vp-JyQHKM3t1LjK_IrlzruU8UCLw6T654uQfEap9xtV8xuWhlPOdq8psqGTD1rev0ZIqXWVaBlsJ9f7M9k_pSA6YmujjxzzlZ4ASP97yNzudu8vSHdT_BL0aEc81-SgtJbw6IAAzcOoA-e6oFQuzoMJ0FhbgJ5H5A9aUtMHX9qXXVIRefzy3bkGtxTvwuJt3FyesHpxzQ",
      "use": "sig",
      "kty": "RSA" as 'RSA',
      "alg": "RS256"
    }
  ]
}
