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
import { JwtAsyncService } from './jwt-async.service';
import { JwtModule } from './jwt.module';
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
    maxAge: 1000 * 60 * 60 * 24 * 20,
  },
};

const options: JwtBlock32Options = {
  accessToken: accessTokenOptions,
  refreshToken: refreshTokenOptions,
};

const serviceSetup = async (jwtOptions: JwtBlock32Options) => {
  const module = await Test.createTestingModule({
    imports: [JwtModule.forRoot(jwtOptions)],
  }).compile();

  return module.get<JwtAsyncService>(JwtAsyncService);
};

describe('Test jwt flow without mocks', () => {
  let jwtService: JwtAsyncService;
  beforeAll(async () => {
    jwtService = await serviceSetup(options);
  });

  let testData = {
    stringPayload: 'test',
    bufferPayload: Buffer.from('TestData', 'base64'),
  };

  it('test whole flow with string secret', async () => {
    //it should throw because sign options can't contain expiresIn if payload is string
    await expect(
      jwtService.signAccessAsync(testData.stringPayload),
    ).rejects.toThrow();

    let token = await jwtService.signAccessAsync({
      data: testData.stringPayload,
    });
    expect(token).toBeDefined();

    await expect(jwtService.verifyAccessAsync(token)).resolves.toMatchObject({
      data: testData.stringPayload,
    });

    token = await jwtService.signAccessAsync({ data: testData.bufferPayload });
    expect(token).toBeDefined();

    const payload = await jwtService.verifyAccessAsync(token);

    expect(payload['data']).toMatchObject(testData.bufferPayload.toJSON());
  });
});

describe('JwtAsyncService tests with mocks', () => {
  let signSpy: jest.SpyInstance;
  let verifySpy: jest.SpyInstance;

  beforeEach(() => {
    signSpy = jest
      .spyOn(jwt, 'sign')
      .mockImplementation((payload: string, secret: any, options, callback) => {
        const mockResult = payload + '_' + (secret as string);
        return callback ? callback(null, mockResult) : mockResult;
      });
    verifySpy = jest
      .spyOn(jwt, 'verify')
      .mockImplementation((token, secret, options, callback) => {
        const mockResult = token + '_' + (secret as string);
        return callback ? callback(null, mockResult) : mockResult;
      });
  });

  afterEach(() => {
    signSpy.mockRestore();
    verifySpy.mockRestore();
  });

  describe('Test JwtAsyncService when secret is provided', () => {
    let jwtService: JwtAsyncService;

    beforeEach(async () => {
      jwtService = await serviceSetup(options);
    });

    it('should sign access token', async () => {
      await expect(jwtService.signAccessAsync('test')).resolves.toBe(
        'test_access_secret',
      );
    });

    it('should sign refresh token', async () => {
      await expect(jwtService.signRefreshAsync('test')).resolves.toBe(
        'test_refresh_secret',
      );
    });

    it('should verify access token', async () => {
      await expect(jwtService.verifyAccessAsync('test_token')).resolves.toBe(
        'test_token_access_secret',
      );
    });

    it('should verify refresh token', async () => {
      await expect(jwtService.verifyRefreshAsync('test_token')).resolves.toBe(
        'test_token_refresh_secret',
      );
    });

    it('should throw SecretKeyError if secret is not provided for access token', async () => {
      const badOptions: JwtBlock32Options = {
        accessToken: {
          ...accessTokenOptions,
          keyOptions: {
            algorithm: 'HS256',
            secret: null as any,
          },
        },
      };

      jwtService = await serviceSetup(badOptions);

      await expect(jwtService.signAccessAsync('test')).rejects.toThrow(
        new SecretKeyError(),
      );
    });

    it('should throw an error if sign is not able to provide valid token', async () => {
      signSpy = jest
        .spyOn(jwt, 'sign')
        .mockImplementationOnce((payload, secret, options, callback) => {
          return callback ? callback(null, undefined) : undefined;
        });
      await expect(jwtService.signAccessAsync('test')).rejects.toThrow(
        'Token not generated',
      );
    });

    it('should throw an error if verify is not able to return payload', async () => {
      verifySpy = jest
        .spyOn(jwt, 'verify')
        .mockImplementationOnce((token, secret, options, callback) => {
          return callback ? callback(null, undefined) : undefined;
        });
      await expect(jwtService.verifyAccessAsync('test')).rejects.toThrow(
        'Token failed to be verified',
      );
    });
  });

  describe('Test JwtAsyncService accessToken for private/public keys', () => {
    let jwtService: JwtAsyncService;
    const { privateKey, publicKey } = generateKeyPairSync('rsa', {
      modulusLength: 384 * 8,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    let testData = {
      test: 'testValue',
    };

    beforeAll(async () => {
      let privateKeyMock: KeyObject = createPrivateKey(privateKey);
      let publicKeyMock: KeyObject = createPublicKey(publicKey);
      let mockOptions: JwtBlock32Options = {
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

    it('should be able to verify after sign', async () => {
      const token = await jwtService.signAccessAsync(testData);

      expect(token).toBeDefined();

      await expect(jwtService.verifyAccessAsync(token)).resolves.toHaveProperty(
        'test',
        'testValue',
      );
    });
  });
});
