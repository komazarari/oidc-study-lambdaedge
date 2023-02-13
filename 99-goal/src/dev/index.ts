import express, { Request, Response, NextFunction } from 'express';
import Cookie from 'cookie';
import { CloudFrontHeaders, CloudFrontRequest, CloudFrontResultResponse } from 'aws-lambda';
const app: express.Application = express();
const port = process.env.PORT || 3000;
const publicDir = process.env.PUBLIC_DIR || 'public';

process.env.IS_DEVELOP = '1';
import { authenticate } from '../app';

/**
 * authenticateMiddleware
 * @param {Request} req
 * @param {Response} res
 * @param {NextFunction} next
 */
async function authenticateMiddleware(req: Request, res: Response, next: NextFunction) {
  const cfRequest = convertExpressRequestToCloudFrontRequest(req);

  const authResult = await authenticate(cfRequest);
  //console.log('authResult:', JSON.stringify(authResult, null, 2))
  if (authResult.authenticated) {
    next();
  } else {
    if (authResult.response) {
      sendResponseFromCloudFrontRequestResult(res, authResult.response as CloudFrontResultResponse);
    } else {
      sendInternalServerError(res, { name: 'Unknown error', message: 'Invalid auth response' });
    }
  }
}

app.use(authenticateMiddleware);
app.use(express.static(publicDir));

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});



function convertExpressRequestToCloudFrontRequest(req: Request): CloudFrontRequest {
  const headers: CloudFrontHeaders = {};
  Object.entries(req.headers).forEach(([key, originalValue]) => {
    if (originalValue) {
      const value = Array.isArray(originalValue) ? originalValue.join(',') : originalValue;
      headers[key] = [{ key, value }];
    }
  });

  return {
    clientIp: req.ip,
    method: req.method,
    uri: req.url,
    querystring: new URLSearchParams(req.query as any).toString(),
    headers: headers,
  };
}

function sendResponseFromCloudFrontRequestResult(res: Response, cfRes: CloudFrontResultResponse) {
  if (!cfRes || !cfRes.status) {
    return sendInternalServerError(res, { name: 'Invalid response status', message: 'empty' });
  }
  res.status(Number(cfRes.status));

  if (cfRes.headers) {
    if (cfRes.headers['set-cookie']) {
      cfRes.headers['set-cookie'].forEach((e) => {
        const parsedCookie = Cookie.parse(e.value);
        const name = Object.keys(parsedCookie)[0];
        const options: Record<string, string | Date> = {};
        const keysMap = {
          Path: 'path',
          'Max-Age': 'maxAge',
          Expires: 'expires',
          HttpOnly: 'httpOnly',
        } as Record<string, string>;
        Object.keys(keysMap).forEach((key) => {
          if (parsedCookie[key]) {
            if (key === 'Expires') {
              options[keysMap[key]] = new Date(parsedCookie[key]);
            } else if (key === 'Max-Age') {
              options[keysMap[key]] = (Number(parsedCookie[key]) * 1000).toString();
            } else {
              options[keysMap[key]] = parsedCookie[key];
            }
          }
        });
        res.cookie(name, parsedCookie[name], options);
      });
    }
    Object.keys(cfRes.headers).forEach((e) => {
      if (e !== 'set-cookie' && cfRes.headers) {
        res.header(e, cfRes.headers[e][0].value);
      }
    });
  }
  res.send(cfRes.body);
}

function sendInternalServerError(res: Response, err?: Error) {
  res.status(500);
  res.send(`Internal Server Error: ${err?.name || 'Unknown Error'} - ${err?.message || ''}`);
}
