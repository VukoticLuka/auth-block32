import * as jwt from 'jsonwebtoken';

export abstract class JwtAsyncDomain {
  abstract signAccessAsync<T extends object | string | Buffer>(
    payload: T,
  ): Promise<string>;
  abstract signRefreshAsync<T extends object | string | Buffer>(
    payload: T,
  ): Promise<string>;
  abstract verifyAccessAsync<T extends object>(token: string): Promise<T>;
  abstract verifyRefreshAsync<T extends object>(token: string): Promise<T>;
  abstract decode(
    token: string,
    options?: jwt.DecodeOptions,
  ): null | string | jwt.JwtPayload;
}
