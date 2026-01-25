import { Injectable, Inject, Logger } from '@nestjs/common';
import {
  DEFAULT_ACCESS_COOKIE_NAME,
  DEFAULT_HEADER_NAME,
  DEFAULT_HEADER_PREFIX,
  DEFAULT_REFRESH_COOKIE_NAME,
  JWT_OPTIONS,
} from './constants';
import {
  JwtBlock32Options,
  TokenType,
  TokenOptionsMap,
  HeaderStorageOptions,
  CookieStorageOptions,
  HttpRequest,
  HttpResponse,
} from './interfaces';
import {
  EmptyCookieError,
  RefreshTokenError,
  UndefinedCookieRequestError,
  WrongAuthHeaderTypeError,
} from './jwt.errors';
import { RefreshCookieOptions } from './interfaces/core-options.interface';
import { TokenStorageDomain } from './domains';

@Injectable()
export class TokenService implements TokenStorageDomain {
  private readonly logger = new Logger(TokenService.name);

  constructor(
    @Inject(JWT_OPTIONS)
    private readonly jwtOptions: JwtBlock32Options,
  ) {}

  setAccessTokenToStorage(res: HttpResponse, token: string): void {
    const tokenOptions = this.getTokenOptions(TokenType.ACCESS);
    if (tokenOptions.storage === 'header') {
      const options = tokenOptions as HeaderStorageOptions;
      const prefix = options.headerOptions.prefix ?? DEFAULT_HEADER_PREFIX;
      res.setHeader(
        options.headerOptions.headerName ?? DEFAULT_HEADER_NAME,
        `${prefix} ${token}`,
      );
    } else if (tokenOptions.storage === 'cookie') {
      const options = tokenOptions as CookieStorageOptions;
      const { cookieName, ...coreOptions } = options.cookieOptions;
      res.cookie(cookieName ?? DEFAULT_ACCESS_COOKIE_NAME, token, {
        ...coreOptions,
      });
    }
  }

  setRefreshTokenToStorage(res: HttpResponse, token: string): void {
    const refreshTokenOptions = this.getTokenOptions(TokenType.REFRESH);
    const { cookieName, ...coreOptions } =
      refreshTokenOptions.cookieOptions as RefreshCookieOptions;
    res.cookie(cookieName ?? DEFAULT_REFRESH_COOKIE_NAME, token, {
      ...coreOptions,
    });
  }

  getAccessTokenFromStorage(req: HttpRequest): string | undefined {
    const tokenOptions = this.getTokenOptions(TokenType.ACCESS);
    if (tokenOptions.storage === 'header') {
      const headerName =
        tokenOptions.headerOptions.headerName ||
        DEFAULT_HEADER_NAME.toLocaleLowerCase();
      const header = req.headers[headerName];
      if (typeof header !== 'string') {
        throw new WrongAuthHeaderTypeError('Missing authorization header');
      }

      const token = header.split(' ')[1].trim();
      if (!token) {
        throw new UndefinedCookieRequestError(
          'Cookies do not exist for provided HttpRequest object',
        );
      }

      return token;
    } else if (tokenOptions.storage === 'cookie') {
      const cookieName =
        tokenOptions.cookieOptions.cookieName || DEFAULT_ACCESS_COOKIE_NAME;
      if (!req.cookies) {
        throw new UndefinedCookieRequestError(
          'Cookies do not exist for provided HttpRequest object',
        );
      }

      const token = req.cookies[cookieName];

      if (!token) {
        throw new EmptyCookieError(
          `Cookie ${cookieName} has empty or undefined value`,
        );
      }

      return token;
    }
  }

  getRefreshTokenFromStorage(req: HttpRequest): string | undefined {
    const tokenOptions = this.getTokenOptions(TokenType.REFRESH);
    const cookieName =
      tokenOptions.cookieOptions?.cookieName || DEFAULT_REFRESH_COOKIE_NAME;

    if (!req.cookies) {
      throw new UndefinedCookieRequestError(
        'Cookies do not exist for provided HttpRequest object',
      );
    }

    const token = req.cookies[cookieName].trim();

    if (!token) {
      throw new EmptyCookieError(
        `Cookie ${cookieName} has empty or undefined value`,
      );
    }

    return token;
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
