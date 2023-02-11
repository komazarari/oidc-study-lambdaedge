import { CloudFrontRequest, CloudFrontRequestResult, CloudFrontHeaders } from 'aws-lambda';

export interface AuthenticationResult {
  authenticated: boolean;
  response: CloudFrontRequestResult;
}

async function authenticate(request: CloudFrontRequest): Promise<AuthenticationResult> {
  return { authenticated: true, response: null };
}

export { authenticate };
