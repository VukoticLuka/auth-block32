import { Inject, Injectable, Optional, Logger } from '@nestjs/common';
import { JwtAsyncDomain } from './domains';
import { JWT_OPTIONS } from './constants';
import {
  CoreTokenOptions,
  JwtBlock32Options,
  RequestType,
  TokenType,
} from './interfaces';
import { RefreshTokenError, SecretKeyError } from './jwt.errors';
import * as jwt from 'jsonwebtoken';

@Injectable()
export class JwtAsyncService implements JwtAsyncDomain {
  private readonly logger = new Logger(JwtAsyncService.name);

  constructor(
    @Optional()
    @Inject(JWT_OPTIONS)
    private readonly jwtOptions: JwtBlock32Options,
  ) {}

  signAccessAsync<T extends object | string | Buffer>(
    payload: T,
  ): Promise<string> {
    const options = this.getCoreOptions(TokenType.ACCESS);
    return this.signAsync(payload, options);
  }

  signRefreshAsync<T extends object | string | Buffer>(
    payload: T,
  ): Promise<string> {
    const options = this.getCoreOptions(TokenType.REFRESH);
    return this.signAsync(payload, options);
  }

  signAsync<T extends object | string | Buffer>(
    payload: T,
    options: CoreTokenOptions,
  ): Promise<string> {
    const secret = this.getSecretValue(options, RequestType.SIGN);
    return new Promise((resolve, reject) => {
      jwt.sign(
        payload,
        secret,
        {
          ...options.signOptions,
          algorithm: options.keyOptions.algorithm,
        },
        (err, token) => {
          if (err) return reject(err);
          if (!token) return reject(new Error('Token not generated'));
          resolve(token);
        },
      );
    });
  }

  verifyAccessAsync<T extends object>(token: string): Promise<T> {
    const options = this.getCoreOptions(TokenType.ACCESS);
    return this.verifyAsync(token, options);
  }

  verifyRefreshAsync<T extends object>(token: string): Promise<T> {
    const options = this.getCoreOptions(TokenType.REFRESH);
    return this.verifyAsync(token, options);
  }

  verifyAsync<T extends object>(
    token: string,
    options: CoreTokenOptions,
  ): Promise<T> {
    const secret = this.getSecretValue(options, RequestType.VERIFY);

    return new Promise((resolve, reject) => {
      jwt.verify(
        token,
        secret,
        {
          ...options?.verifyOptions,
          algorithms: [options.keyOptions.algorithm],
        },
        (err, payload) => {
          if (err) return reject(err);
          if (!payload)
            return reject(new Error('Token failed to be verified!'));
          resolve(payload as T);
        },
      );
    });
  }

  decode(
    token: string,
    options?: jwt.DecodeOptions,
  ): null | string | jwt.JwtPayload {
    return jwt.decode(token, options);
  }

  private getSecretValue(
    options: CoreTokenOptions,
    requestType: RequestType,
  ): jwt.Secret {
    const keyMap: Record<RequestType, 'privateKey' | 'publicKey'> = {
      [RequestType.SIGN]: 'privateKey',
      [RequestType.VERIFY]: 'publicKey',
    };

    const secret =
      options?.keyOptions?.secret ?? options?.keyOptions?.[keyMap[requestType]];

    if (!secret) {
      this.logger.error(
        `Neither secret nor ${keyMap[requestType]} are provided`,
      );
      throw new SecretKeyError();
    }

    return secret;
  }

  private getCoreOptions(tokenType: TokenType): CoreTokenOptions {
    const options =
      tokenType === TokenType.ACCESS
        ? this.jwtOptions.accessToken
        : this.jwtOptions.refreshToken;
    if (!options) {
      this.logger.error(`${tokenType} token options are missing`);
      throw new RefreshTokenError();
    }
    return options;
  }
}
