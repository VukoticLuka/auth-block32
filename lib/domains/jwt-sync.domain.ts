import * as jwt from 'jsonwebtoken';

export abstract class JwtAsyncDomain {
  abstract sign<T extends object | string | Buffer>(
    payload: T,
    options?: jwt.SignOptions,
  ): string;
  abstract verify<T extends object>(
    token: string,
    options?: jwt.VerifyOptions,
  ): T;
  abstract decode(
    token: string,
    options?: jwt.DecodeOptions,
  ): null | string | jwt.JwtPayload;
}
