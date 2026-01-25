import { Test } from '@nestjs/testing';
import { JwtAsyncGuard } from './jwtAsync.guard';
import { TokenService } from '../token.service';
import { JwtAsyncService } from '../jwt-async.service';
import {
  AccessTokenOptions,
  HttpRequest,
  HttpResponse,
  JwtBlock32Options,
  RefreshTokenOptions,
} from '../interfaces';
import { JwtModule } from '../jwt.module';
import { ExecutionContext } from '@nestjs/common';

const accessTokenOptions: AccessTokenOptions = {
  keyOptions: {
    algorithm: 'HS256',
    secret: 'access_secret',
  },
  signOptions: {
    expiresIn: '15m',
  },
  verifyOptions: {
    maxAge: '15m',
    ignoreExpiration: false,
  },
  storage: 'header',
  headerOptions: {
    headerName: 'authorization',
    prefix: 'Bearer',
  },
};

const refreshTokenOptions: RefreshTokenOptions = {
  keyOptions: {
    algorithm: 'HS256',
    secret: 'refresh_secret',
  },
  signOptions: {
    expiresIn: '20d',
  },
  verifyOptions: {
    maxAge: '20d',
    ignoreExpiration: false,
  },
  cookieOptions: {
    cookieName: 'RefreshToken',
    secure: true,
    path: '/',
    // max age her is 20 days
    maxAge: 1000 * 60 * 60 * 24 * 20,
  },
};

const options: JwtBlock32Options = {
  accessToken: accessTokenOptions,
  refreshToken: refreshTokenOptions,
};

type MockHttpState = {
  headers: Record<string, string>;
  cookies: Record<string, string>;
};

describe('Test jwtAsyncGuard', () => {
  let guard: JwtAsyncGuard;
  let tokenService: TokenService;
  let jwtService: JwtAsyncService;

  beforeEach(async () => {
    const module = await Test.createTestingModule({
      imports: [JwtModule.forRoot(options)],
    }).compile();

    guard = module.get<JwtAsyncGuard>(JwtAsyncGuard);
    tokenService = module.get<TokenService>(TokenService);
    jwtService = module.get<JwtAsyncService>(JwtAsyncService);
  });

  const mockExecutionContext = (req: HttpRequest): ExecutionContext =>
    ({
      switchToHttp: () => ({
        getRequest: () => req,
      }),
    }) as unknown as ExecutionContext;

  const createMockResponse = (state: MockHttpState): HttpResponse => ({
    setHeader: (key: string, value: string) => {
      state.headers[key.toLowerCase()] = value;
    },
    cookie: (name: string, value: string) => {
      state.cookies[name] = value;
    },
  });

  const createMockRequest = (state: MockHttpState): HttpRequest => ({
    headers: state.headers,
    cookies: state.cookies,
  });

  const payload = {
    sub: '123',
    email: 'test@example.com',
  };

  it('should return true when access token is there and false when its not', async () => {
    const token = await jwtService.signAccessAsync(payload);

    expect(typeof token).toBe('string');

    //mock req
    const req = {
      headers: {
        authorization: `Bearer ${token}`,
      },
    };

    let context = mockExecutionContext(req);

    const result = await guard.canActivate(context);

    expect(result).toBe(true);

    const badReq = {
      headers: {},
    };

    context = mockExecutionContext(badReq);

    await expect(guard.canActivate(context)).resolves.toBe(false);
  });

  it('test guard with using token service', async () => {
    const createMockHttp = () => {
      const state: MockHttpState = {
        headers: {},
        cookies: {},
      };

      return {
        state,
        res: createMockResponse(state),
        req: createMockRequest(state),
      };
    };

    const { req, res } = createMockHttp();

    const token = await jwtService.signAccessAsync(payload);

    tokenService.setAccessTokenToStorage(res, token);

    const context = mockExecutionContext(req);

    await expect(guard.canActivate(context)).resolves.toBe(true);
  });
});
