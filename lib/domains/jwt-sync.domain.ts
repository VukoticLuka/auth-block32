import * as jwt from 'jsonwebtoken';

export abstract class JwtSyncDomain {
  abstract signAccessSync<T extends object | string | Buffer>(
    payload: T,
  ): string;
  abstract signRefreshSync<T extends object | string | Buffer>(
    payload: T,
  ): string;
  abstract verifyAccessSync<T extends object>(token: string): T;
  abstract verifyRefreshSync<T extends object>(token: string): T;
  abstract decode(
    token: string,
    options?: jwt.DecodeOptions,
  ): null | string | jwt.JwtPayload;
}
