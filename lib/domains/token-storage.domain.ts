import { HttpRequest, HttpResponse } from '../interfaces';

export abstract class TokenStorageDomain {
  public abstract setAccessTokenToStorage(
    res: HttpResponse,
    token: string,
  ): void;
  public abstract setRefreshTokenToStorage(
    res: HttpResponse,
    token: string,
  ): void;
  public abstract getAccessTokenFromStorage(
    req: HttpRequest,
  ): string | undefined;
  public abstract getRefreshTokenFromStorage(
    req: HttpRequest,
  ): string | undefined;
}
