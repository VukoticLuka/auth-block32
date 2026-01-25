import {
  CanActivate,
  ExecutionContext,
  Injectable,
  Logger,
} from '@nestjs/common';
import { TokenService } from './token.service';
import { JwtAsyncService } from './jwt-async.service';
import { UndefinedTokenError } from './jwt.errors';
import { HttpRequest } from './interfaces';

@Injectable()
export class JwtAsyncGuard implements CanActivate {
  private readonly logger = new Logger(JwtAsyncGuard.name);

  constructor(
    private readonly tokenService: TokenService,
    private readonly jwtAsyncService: JwtAsyncService,
  ) {}
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req: HttpRequest = context.switchToHttp().getRequest();
    try {
      const token = this.tokenService.getAccessTokenFromStorage(req);
      if (!token) {
        this.logger.warn('Token is undefined');
        throw new UndefinedTokenError();
      }
      const payload = await this.jwtAsyncService.verifyAccessAsync(token);
      return !!payload;
    } catch (err) {
      this.logger.warn(err);
      return false;
    }
  }
}
