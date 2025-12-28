import * as jwt from 'jsonwebtoken';
import { CoreTokenOptions } from 'lib/interfaces';

export abstract class JwtAsyncDomain {
  abstract signAsync<T extends object | string | Buffer>(
    payload: T,
    options: CoreTokenOptions,
  ): Promise<string>;
  abstract verifyAsync<T extends object>(
    token: string,
    options: CoreTokenOptions,
  ): Promise<T>;
  abstract decode(
    token: string,
    options?: jwt.DecodeOptions,
  ): null | string | jwt.JwtPayload;
}
