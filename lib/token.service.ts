import { Injectable, Inject, Logger } from '@nestjs/common';
import {
  DEFAULT_ACCESS_COOKIE_NAME,
  DEFAULT_HEADER_NAME,
  DEFAULT_HEADER_PREFIX,
  DEFAULT_REFRESH_COOKIE_NAME,
  JWT_OPTIONS,
} from './constants';
import { Response } from 'express';
import {
  JwtBlock32Options,
  TokenType,
  TokenOptionsMap,
  HeaderStorageOptions,
  CookieStorageOptions,
} from './interfaces';
import { RefreshTokenError } from './jwt.errors';
import { RefreshCookieOptions } from './interfaces/core-options.interface';

@Injectable()
export class TokenService {
  private readonly logger = new Logger(TokenService.name);

  constructor(
    @Inject(JWT_OPTIONS)
    private readonly jwtOptions: JwtBlock32Options,
  ) {}

  setAccessTokenToStorage(res: Response, token: string): void {
    const tokenOptions = this.getTokenOptions(TokenType.ACCESS);
    if (tokenOptions.storage === 'header') {
      const options = tokenOptions as HeaderStorageOptions;
      const prefix = options.headerOptions.prefix ?? DEFAULT_HEADER_PREFIX;
      res.setHeader(
        options.headerOptions.headerName ?? DEFAULT_HEADER_NAME,
        `${prefix}${token}`,
      );
    } else if (tokenOptions.storage === 'cookie') {
      const options = tokenOptions as CookieStorageOptions;
      const { cookieName, ...coreOptions } = options.cookieOptions;
      res.cookie(cookieName ?? DEFAULT_ACCESS_COOKIE_NAME, token, {
        ...coreOptions,
      });
    }
  }

  setRefreshTokenToStorage(res: Response, token: string): void {
    const refreshTokenOptions = this.getTokenOptions(TokenType.REFRESH);
    const { cookieName, ...coreOptions } =
      refreshTokenOptions.cookieOptions as RefreshCookieOptions;
    res.cookie(cookieName ?? DEFAULT_REFRESH_COOKIE_NAME, token, {
      ...coreOptions,
    });
  }

  private getTokenOptions<T extends TokenType>(
    tokenType: T,
  ): TokenOptionsMap[T] {
    const options =
      tokenType === TokenType.ACCESS
        ? this.jwtOptions.accessToken
        : this.jwtOptions.refreshToken;
    if (!options) {
      this.logger.error(`${tokenType} token options are missing`);
      throw new RefreshTokenError();
    }
    return options as TokenOptionsMap[T];
  }
}
