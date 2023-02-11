import { CloudFrontRequestEvent, CloudFrontRequestResult } from 'aws-lambda';
import { authenticate } from '../app';

export const handler = async (event: CloudFrontRequestEvent): Promise<CloudFrontRequestResult> => {
  const request = event.Records[0].cf.request;

  const authResult = await authenticate(request);
  if (authResult.authenticated) {
    return request;
  } else {
    return authResult.response;
  }
};
