import { CloudFrontRequest, CloudFrontRequestResult, CloudFrontHeaders, CloudFrontResultResponse } from 'aws-lambda';
import Axios from 'axios';
import Cookie from 'cookie';
import JsonWebToken, { JwtPayload } from 'jsonwebtoken';
import JwkToPem from 'jwk-to-pem';
import QueryString, { ParsedUrlQuery } from 'querystring';
import { assert } from 'console';


export interface AuthenticationResult {
  authenticated: boolean;
  response: CloudFrontRequestResult;
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
  const { headers, querystring } = request;
  const queryString = QueryString.parse(querystring);

  if (request.uri.startsWith('/_callback')) {
    return handleCallback(request, queryString);
  }

  const authTokenCookieValue = getCookieValue(headers, 'TOKEN');
  if (!authTokenCookieValue) {
    return { authenticated: false, response: oidcRedirectResponse(request) };
  }

  const [verifyOk, err] = await verifyToken(authTokenCookieValue);
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
  try {
    const tokenRequest = {
      client_id: process.env.CLIENT_ID, // Todo
      client_secret: process.env.CLIENT_SECRET, // Todo
      grant_type: 'authorization_code',
      redirect_uri: 'http://localhost:3000/_callback',
      code: queryString.code,
    }

    const idToken = await IdToken.get('https://oauth2.googleapis.com/token', tokenRequest);
    const rawPem = tmpJwks.keys.find((key) => key.kid === idToken.decoded.header.kid);
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

async function verifyToken(authToken: string): Promise<[boolean, Error | null]> {
  console.log('ToDo: verifyToken');
  return [true, null];
}

// --------------------
// global variables
// --------------------
async function prepareGlobals() {
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
  const authRequest = {
    client_id: process.env.CLIENT_ID,
    response_type: 'code',
    scope: 'openid email',
    redirect_uri: 'http://localhost:3000/_callback',
    state: request.uri
  }

  const response = {
    status: '302',
    statusDescription: 'Found',
    body: 'Redirecting...',
    headers: {
      location: [{
        key: 'Location',
        value: `https://accounts.google.com/o/oauth2/v2/auth?${QueryString.stringify(authRequest)}`
      }],
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
