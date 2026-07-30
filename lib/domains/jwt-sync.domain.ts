import * as jwt from 'jsonwebtoken';
import { SignOptions, VerifyOptions } from '../interfaces';

export abstract class JwtSyncDomain {
  abstract signAccessSync<T extends object | string | Buffer>(
    payload: T,
    signOptions?: SignOptions,
  ): string;
  abstract signRefreshSync<T extends object | string | Buffer>(
    payload: T,
    signOptions?: SignOptions,
  ): string;
  abstract verifyAccessSync<T extends object>(
    token: string,
    verifyOptions?: VerifyOptions,
  ): T;
  abstract verifyRefreshSync<T extends object>(
    token: string,
    verifyOptions?: VerifyOptions,
  ): T;
  abstract decode(
    token: string,
    options?: jwt.DecodeOptions,
  ): null | string | jwt.JwtPayload;
}
