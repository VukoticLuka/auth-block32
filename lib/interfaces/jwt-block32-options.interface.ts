import * as jwt from 'jsonwebtoken';
import {
  CoreCookieOptions,
  CoreHeaderOptions,
  RefreshCookieOptions,
  KeyOptions,
} from './core-options.interface';

export enum RequestType {
  SIGN = 'sign',
  VERIFY = 'verify',
}

export enum TokenType {
  ACCESS = 'access',
  REFRESH = 'refresh',
}

export type TokenOptionsMap = {
  [TokenType.ACCESS]: AccessTokenOptions;
  [TokenType.REFRESH]: RefreshTokenOptions;
};

export type CookieStorageOptions = {
  storage: 'cookie';
  cookieOptions: Partial<CoreCookieOptions>;
};

export type HeaderStorageOptions = {
  storage: 'header';
  headerOptions: Partial<CoreHeaderOptions>;
};
export type SignOptions = Omit<jwt.SignOptions, 'algorithm'>;
export type VerifyOptions = Omit<jwt.VerifyOptions, 'algorithm'>;

export type CoreTokenOptions = {
  keyOptions: KeyOptions;
  signOptions?: SignOptions;
  verifyOptions?: VerifyOptions;
};

export type AccessTokenOptions = CoreTokenOptions &
  (HeaderStorageOptions | CookieStorageOptions);

export type RefreshTokenOptions = CoreTokenOptions & {
  cookieOptions?: Partial<RefreshCookieOptions>;
};

export type JwtBlock32Options = {
  accessToken: AccessTokenOptions;
  refreshToken?: RefreshTokenOptions;
};
