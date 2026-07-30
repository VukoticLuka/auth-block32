import { Injectable, Inject, Logger, Optional } from '@nestjs/common';
import { JwtSyncDomain } from './domains';
import { JWT_OPTIONS } from './constants';
import {
  CoreTokenOptions,
  GetSecretValue,
  JwtBlock32Options,
  KeyOptions,
  RequestType,
  SignOptions,
  TokenType,
  VerifyOptions,
} from './interfaces';
import * as jwt from 'jsonwebtoken';
import {
  AsyncSecretOrKeyProviderError,
  SecretKeyError,
  TokenOptionsError,
} from './jwt.errors';

@Injectable()
export class JwtSyncService implements JwtSyncDomain {
  private readonly logger = new Logger(JwtSyncService.name);

  constructor(
    @Optional()
    @Inject(JWT_OPTIONS)
    private readonly jwtOptions: JwtBlock32Options,
  ) {}

  signAccessSync<T extends object | string | Buffer>(
    payload: T,
    signOptions?: SignOptions,
  ): string {
    const options = this.getCoreOptions(TokenType.ACCESS);
    return this.signSync(payload, {
      ...options,
      signOptions: {
        ...options.signOptions,
        ...signOptions,
      },
    });
  }

  signRefreshSync<T extends object | string | Buffer>(
    payload: T,
    signOptions?: SignOptions,
  ): string {
    const options = this.getCoreOptions(TokenType.REFRESH);
    return this.signSync(payload, {
      ...options,
      signOptions: {
        ...options.signOptions,
        ...signOptions,
      },
    });
  }

  private signSync<T extends object | string | Buffer>(
    payload: T,
    options: CoreTokenOptions,
  ): string {
    const secret = this.getSecretOrKey(
      options.keyOptions,
      payload,
      RequestType.SIGN,
      options.signOptions ?? {},
    );

    if (secret instanceof Promise) {
      secret.catch(() => {
        this.logger.warn(
          'You are using async version of "secretOrKeyProvider". You should consider using JwtAsyncService.',
        );
      });
      throw new AsyncSecretOrKeyProviderError();
    }

    return jwt.sign(payload, secret, {
      ...options?.signOptions,
      algorithm: options.keyOptions.algorithm,
    });
  }

  verifyAccessSync<T extends object>(
    token: string,
    verifyOptions?: VerifyOptions,
  ): T {
    const options = this.getCoreOptions(TokenType.ACCESS);
    return this.verifySync(token, {
      ...options,
      verifyOptions: {
        ...options.verifyOptions,
        ...verifyOptions,
      },
    });
  }

  verifyRefreshSync<T extends object>(
    token: string,
    verifyOptions?: VerifyOptions,
  ): T {
    const options = this.getCoreOptions(TokenType.REFRESH);
    return this.verifySync(token, {
      ...options,
      verifyOptions: {
        ...options.verifyOptions,
        ...verifyOptions,
      },
    });
  }

  private verifySync<T extends object>(
    token: string,
    options: CoreTokenOptions,
  ): T {
    const secret = this.getSecretOrKey(
      options.keyOptions,
      token,
      RequestType.VERIFY,
      options.verifyOptions ?? {},
    );

    if (secret instanceof Promise) {
      secret.catch(() => {
        this.logger.warn(
          'You are using async version of "secretOrKeyProvider". You should consider using JwtAsyncService.',
        );
      });
      throw new AsyncSecretOrKeyProviderError();
    }

    return jwt.verify(token, secret, {
      ...options?.verifyOptions,
      algorithms: [options.keyOptions.algorithm],
    }) as T;
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
