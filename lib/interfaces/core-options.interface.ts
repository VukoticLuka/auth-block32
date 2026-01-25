import * as jwt from 'jsonwebtoken';

export enum RequestType {
  SIGN = 'sign',
  VERIFY = 'verify',
}

export enum TokenType {
  ACCESS = 'access',
  REFRESH = 'refresh',
}

export type CoreCookieOptions = {
  cookieName: string;
  httpOnly: boolean;
  secure: boolean;
  sameSite: 'strict' | 'lax' | 'none';
  path: string;
  maxAge: number;
};

export type CoreHeaderOptions = {
  headerName: string;
  prefix: string;
};

export type RefreshCookieOptions = Omit<
  CoreCookieOptions,
  'httpOnly' | 'sameSite'
> & {
  httpOnly: true;
  sameSite: 'strict';
};

export type HmacAlgorithm = 'HS256' | 'HS384' | 'HS512';

export type RsaAlgorithm = 'RS256' | 'RS384' | 'RS512';

export type KeyOptions = {
  algorithm: HmacAlgorithm | RsaAlgorithm;
  secret?: jwt.Secret;
  privateKey?: jwt.Secret;
  publicKey?: jwt.Secret;
  secretOrKeyProvider?: (
    requestType: RequestType,
    tokenOrPayload: string | object | Buffer,
    requestOptions: jwt.SignOptions | jwt.VerifyOptions,
  ) => GetSecretValue;
};

export type GetSecretValue = jwt.Secret | Promise<jwt.Secret>;
