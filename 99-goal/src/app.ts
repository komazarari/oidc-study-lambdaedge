import { CloudFrontRequest, CloudFrontRequestResult, CloudFrontHeaders } from 'aws-lambda';
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

  if (request.uri.startsWith('/_callback')) {
    return handleCallback(request);
  }

  const authTokenCookieValue = 'dummyToken';
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

async function handleCallback(request: CloudFrontRequest): Promise<AuthenticationResult> {
  return {
    authenticated: false,
    response: {
      status: '200',
      statusDescription: 'OK',
      body: 'ToDo: redirect',
    }
  };
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
  return {
    status: '200',
    statusDescription: 'OK',
    body: 'ToDo: redirect',
  }
  /* return {
    status: '302',
    statusDescription: 'Found',
    headers: {
      location: [{ key: 'Location', value: redirectUrl }],
    },
  }; */
}


// --------------------
// tmp functions
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
