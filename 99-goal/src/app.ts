import { CloudFrontRequest, CloudFrontRequestResult, CloudFrontHeaders, CloudFrontResultResponse } from 'aws-lambda';

import { Config, fetchConfigFromSecretsManager, fetchConfigFromFile, AuthRequest } from './config';
import Axios from 'axios';
import Cookie from 'cookie';
import JsonWebToken, { JwtPayload } from 'jsonwebtoken';
import jwkToBuffer, { JWK } from 'jwk-to-pem';
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
  jwks: {
    keys: null as (({ kid: string } & JWK)[]) | null,
  },
};

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
  assert(global.config !== null && global.discoveryDocumnet !== null && global.jwks.keys !== null);
  const config = global.config;
  try {
    const tokenRequest = {
      client_id: config.client_id,
      client_secret: config.client_secret,
      grant_type: config.grant_type,
      redirect_uri: `${config.CALLBACK_BASE_URL}${config.CALLBACK_PATH}`,
      code: queryString.code,
    };

    const idToken = await IdToken.get(global.discoveryDocumnet.token_endpoint, tokenRequest);
    const rawPem = global.jwks.keys.find((key) => key.kid === idToken.decoded.header.kid);
    if (rawPem === undefined) {
      throw new Error('unable to find expected pem in JWKs keys');
    }
    const pem = jwkToBuffer(rawPem);
    try {
      const decoded = await verifyJwt(idToken.raw, pem, { algorithms: ['RS256'] });
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
  await setJwks();
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
  assert(global.config !== null);
  const config = global.config;
  global.discoveryDocumnet = (await Axios.get(config.DISCOVERY_DOCUMENT_URL)).data as DiscoveryDocument;
  console.log('discovery document fetched');
}

async function setJwks(): Promise<void> {
  if (global.jwks !== null) return;
  assert(global.discoveryDocumnet !== null);
  // ts-ignore
  global.jwks = (await Axios.get(global.discoveryDocumnet.jwks_uri)).data;
  console.log('jwks fetched', global.jwks);
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
    state: request.uri,
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
