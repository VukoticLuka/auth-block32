import {
  CanActivate,
  ExecutionContext,
  Injectable,
  Logger,
} from '@nestjs/common';
import { TokenService } from './token.service';
import { JwtSyncService } from './jwt-sync.service';
import { UndefinedTokenError } from './jwt.errors';

@Injectable()
export class JwtSyncGuard implements CanActivate {
  private readonly logger = new Logger(JwtSyncGuard.name);

  constructor(
    private readonly tokenService: TokenService,
    private readonly jwtSyncService: JwtSyncService,
  ) {}
  canActivate(context: ExecutionContext): boolean | Promise<boolean> {
    const req = context.switchToHttp().getRequest();
    try {
      const token = this.tokenService.getAccessTokenFromStorage(req);
      if (!token) {
        this.logger.warn('Token is undefined');
        throw new UndefinedTokenError();
      }
      const payload = this.jwtSyncService.verifyAccessSync(token);

      return !!payload;
    } catch (err) {
      this.logger.warn(err);
      return false;
    }
  }
}
