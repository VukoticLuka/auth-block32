export class SecretKeyError extends Error {}
export class RefreshTokenError extends Error {}
export class UndefinedTokenError extends Error {}
export class CreateAsyncJwtProvidersError extends Error {}
export class AsyncSecretOrKeyProviderError extends Error {}
export class WrongAuthHeaderTypeError extends Error {}
export class UndefinedCookieRequestError extends Error {}
export class EmptyCookieError extends Error {}
export class TokenOptionsError extends Error {
  constructor() {
    super('Token options are missing');
  }
}
