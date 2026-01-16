import { Test } from '@nestjs/testing';
import {
  AccessTokenOptions,
  JwtBlock32Options,
  RefreshTokenOptions,
} from './interfaces';
import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  KeyObject,
} from 'crypto';
import { JwtModule } from './jwt.module';
import { JwtSyncService } from './jwt-sync.service';
import * as jwt from 'jsonwebtoken';
import { SecretKeyError } from './jwt.errors';

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
    headerName: 'Authorization',
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

const testData = {
  stringPayload: 'test',
  objPayload: {
    data: 'test',
  },
};

const serviceSetup = async (jwtOptions: JwtBlock32Options) => {
  const module = await Test.createTestingModule({
    imports: [JwtModule.forRoot(jwtOptions)],
  }).compile();

  return module.get<JwtSyncService>(JwtSyncService);
};

const serviceAsyncSetup = async (jwtOptions: JwtBlock32Options) => {
  const module = await Test.createTestingModule({
    imports: [
      JwtModule.forRootAsync({
        useFactory: () => jwtOptions,
        inject: [],
      }),
    ],
  }).compile();

  return module.get<JwtSyncService>(JwtSyncService);
};

describe('Test jwt flow without mocks', () => {
  let jwtService: JwtSyncService;

  beforeAll(async () => {
    jwtService = await serviceSetup(options);
  });

  it('test whole sign and verify flow', () => {
    expect(() => jwtService.signAccessSync(testData.stringPayload)).toThrow();

    const token = jwtService.signAccessSync(testData.objPayload);

    expect(token).toBeDefined();

    expect(jwtService.verifyAccessSync(token)).toMatchObject({
      data: 'test',
    });
  });
});

describe('Test jwt flow without mocks when module is async loaded', () => {
  let jwtService: JwtSyncService;

  beforeAll(async () => {
    jwtService = await serviceAsyncSetup(options);
  });

  it('test whole sign and verify flow', () => {
    expect(() => jwtService.signAccessSync(testData.stringPayload)).toThrow();

    const token = jwtService.signAccessSync(testData.objPayload);

    expect(token).toBeDefined();

    expect(jwtService.verifyAccessSync(token)).toMatchObject({
      data: 'test',
    });
  });
});

describe('JwtAsyncService tests with mocks', () => {
  let signSpy: jest.SpyInstance;
  let verifySpy: jest.SpyInstance;

  beforeEach(() => {
    signSpy = jest
      .spyOn(jwt, 'sign')
      .mockImplementation((payload: string, secret: any, _, callback) => {
        const mockResult = payload + '_' + (secret as string);
        return callback ? callback(null, mockResult) : mockResult;
      });
    verifySpy = jest
      .spyOn(jwt, 'verify')
      .mockImplementation((token, secret, _, callback) => {
        const mockResult = token + '_' + (secret as string);
        return callback ? callback(null, mockResult) : mockResult;
      });
  });

  afterEach(() => {
    signSpy.mockRestore();
    verifySpy.mockRestore();
  });

  describe('Test JwtAsyncService when secret is provided', () => {
    let jwtService: JwtSyncService;

    beforeEach(async () => {
      jwtService = await serviceSetup(options);
    });

    it('should sign access token', () => {
      expect(jwtService.signAccessSync('test')).toBe('test_access_secret');
    });

    it('should sign refresh token', () => {
      expect(jwtService.signRefreshSync('test')).toBe('test_refresh_secret');
    });

    it('should verify access token', () => {
      expect(jwtService.verifyAccessSync('test_token')).toBe(
        'test_token_access_secret',
      );
    });

    it('should verify refresh token', () => {
      expect(jwtService.verifyRefreshSync('test_token')).toBe(
        'test_token_refresh_secret',
      );
    });

    it('should throw SecretKeyError if secret is not provided for access token', async () => {
      const badOptions: JwtBlock32Options = {
        accessToken: {
          ...accessTokenOptions,
          keyOptions: {
            algorithm: 'HS256',
            secret: undefined,
          },
        },
      };

      jwtService = await serviceSetup(badOptions);

      expect(() => jwtService.signAccessSync('test')).toThrow(
        new SecretKeyError(),
      );
    });
  });

  describe('Test JwtAsyncService accessToken for private/public keys', () => {
    let jwtService: JwtSyncService;
    // we are mul 384 by 8 because 1 byte is 8 bits
    const { privateKey, publicKey } = generateKeyPairSync('rsa', {
      modulusLength: 384 * 8,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    const testData = {
      test: 'testValue',
    };

    beforeAll(async () => {
      const privateKeyMock: KeyObject = createPrivateKey(privateKey);
      const publicKeyMock: KeyObject = createPublicKey(publicKey);
      const mockOptions: JwtBlock32Options = {
        accessToken: {
          ...accessTokenOptions,
          keyOptions: {
            algorithm: 'RS384',
            privateKey: privateKeyMock,
            publicKey: publicKeyMock,
          },
        },
      };

      jwtService = await serviceSetup(mockOptions);
    });

    beforeEach(() => {
      signSpy.mockRestore();
      verifySpy.mockRestore();
    });

    it('should be able to verify after sign', () => {
      const token = jwtService.signAccessSync(testData);

      expect(token).toBeDefined();

      expect(jwtService.verifyAccessSync(token)).toHaveProperty(
        'test',
        'testValue',
      );
    });
  });

  describe('Test JwtAsyncService accessToken flow when secret is Buffer', () => {
    let jwtService: JwtSyncService;
    const newSecret: Buffer = Buffer.from('access_secret', 'utf-8');
    const mockOptions: JwtBlock32Options = {
      accessToken: {
        ...accessTokenOptions,
        keyOptions: {
          algorithm: 'HS256',
          secret: newSecret,
        },
      },
    };

    beforeAll(async () => {
      jwtService = await serviceSetup(mockOptions);
    });

    it('test access token sign and verify flow', () => {
      const token = jwtService.signAccessSync('test_data');

      expect(token).toBeDefined();

      expect(jwtService.verifyAccessSync(token)).toContain(
        'test_data_access_secret',
      );
    });
  });
});
