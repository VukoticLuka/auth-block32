import { Inject, Injectable, Optional, Logger } from '@nestjs/common';
import { JwtAsyncDomain } from './domains';
import { JWT_OPTIONS } from './constants';
import {
  CoreTokenOptions,
  JwtBlock32Options,
  RequestType,
  SignOptions,
  TokenType,
  VerifyOptions,
} from './interfaces';
import { SecretKeyError, TokenOptionsError } from './jwt.errors';
import * as jwt from 'jsonwebtoken';
import {
  GetSecretValue,
  KeyOptions,
} from './interfaces/core-options.interface';

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
    signOptions?: SignOptions,
  ): Promise<string> {
    const options = this.getCoreOptions(TokenType.ACCESS);
    return this.signAsync(payload, {
      ...options,
      signOptions: {
        ...options.signOptions,
        ...signOptions,
      },
    });
  }

  signRefreshAsync<T extends object | string | Buffer>(
    payload: T,
    signOptions?: SignOptions,
  ): Promise<string> {
    const options = this.getCoreOptions(TokenType.REFRESH);
    return this.signAsync(payload, {
      ...options,
      signOptions: {
        ...options.signOptions,
        ...signOptions,
      },
    });
  }

  private async signAsync<T extends object | string | Buffer>(
    payload: T,
    options: CoreTokenOptions,
  ): Promise<string> {
    const secret = await this.getSecretOrKey(
      options.keyOptions,
      payload,
      RequestType.SIGN,
      options.signOptions || {},
    );
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

  verifyAccessAsync<T extends object>(
    token: string,
    verifyOptions?: VerifyOptions,
  ): Promise<T> {
    const options = this.getCoreOptions(TokenType.ACCESS);
    return this.verifyAsync(token, {
      ...options,
      verifyOptions: {
        ...options.verifyOptions,
        ...verifyOptions,
      },
    });
  }

  verifyRefreshAsync<T extends object>(
    token: string,
    verifyOptions?: VerifyOptions,
  ): Promise<T> {
    const options = this.getCoreOptions(TokenType.REFRESH);
    return this.verifyAsync(token, {
      ...options,
      verifyOptions: {
        ...options.verifyOptions,
        ...verifyOptions,
      },
    });
  }

  private async verifyAsync<T extends object>(
    token: string,
    options: CoreTokenOptions,
  ): Promise<T> {
    const secret = await this.getSecretOrKey(
      options.keyOptions,
      token,
      RequestType.VERIFY,
      options.verifyOptions || {},
    );

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
          if (!payload) return reject(new Error('Token failed to be verified'));
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

  private getSecretOrKey(
    keyOptions: KeyOptions,
    tokenOrPayload: string | object | Buffer,
    requestType: RequestType,
    requestTypeOptions: jwt.SignOptions | jwt.VerifyOptions,
  ): GetSecretValue {
    const keyMap: Record<RequestType, 'privateKey' | 'publicKey'> = {
      [RequestType.SIGN]: 'privateKey',
      [RequestType.VERIFY]: 'publicKey',
    };

    const secret = keyOptions.secretOrKeyProvider
      ? keyOptions.secretOrKeyProvider(
          requestType,
          tokenOrPayload,
          requestTypeOptions,
        )
      : (keyOptions?.secret ?? keyOptions?.[keyMap[requestType]]);

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
      throw new TokenOptionsError();
    }
    return options;
  }
}
