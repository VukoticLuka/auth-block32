import { Response } from 'express';

export abstract class TokenStorageDomain {
  public abstract setAccessTokenToStorage(res: Response, token: string): void;
  public abstract setRefreshTokenToStorage(res: Response, token: string): void;
}
