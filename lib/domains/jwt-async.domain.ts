import * as jwt from 'jsonwebtoken';
import { SignOptions, VerifyOptions } from '../interfaces';

export abstract class JwtAsyncDomain {
  abstract signAccessAsync<T extends object | string | Buffer>(
    payload: T,
    signOptions?: SignOptions,
  ): Promise<string>;
  abstract signRefreshAsync<T extends object | string | Buffer>(
    payload: T,
    signOptions?: SignOptions,
  ): Promise<string>;
  abstract verifyAccessAsync<T extends object>(
    token: string,
    verifyOptions?: VerifyOptions,
  ): Promise<T>;
  abstract verifyRefreshAsync<T extends object>(
    token: string,
    verifyOptions?: VerifyOptions,
  ): Promise<T>;
  abstract decode(
    token: string,
    options?: jwt.DecodeOptions,
  ): null | string | jwt.JwtPayload;
}
