import { DynamicModule, Logger, Module, Provider } from '@nestjs/common';
import { JwtAsyncService } from './jwt-async.service';
import {
  JwtBlock32Options,
  JwtModuleFactoryOptions,
  JwtModuleOptionsAsync,
} from './interfaces';
import { JWT_OPTIONS } from './constants';
import { CreateAsyncJwtProvidersError } from './jwt.errors';
import { createJwtBlock32Provider } from './jwt.providers';
import { TokenService } from './token.service';
import { JwtSyncService } from './jwt-sync.service';

/*
 * We are not lazy-loading services because they are lightweight.
 * They only store options in their constructors, which is not CPU-intensive.
 * In the future, if we decide to extend this library, we may include lazy loading.
 */
@Module({
  providers: [JwtAsyncService, JwtSyncService, TokenService],
  exports: [JwtAsyncService, JwtSyncService, TokenService],
})
export class JwtModule {
  private static readonly logger = new Logger('JwtModule');

  static forRoot(options: JwtBlock32Options): DynamicModule {
    return {
      module: JwtModule,
      providers: createJwtBlock32Provider(options),
    };
  }

  static forRootAsync(options: JwtModuleOptionsAsync): DynamicModule {
    return {
      module: JwtModule,
      imports: options.imports || [],
      providers: [
        ...this.createAsyncJwtProviders(options),
        ...(options.additionalProviders ?? []),
      ],
    };
  }

  private static createAsyncJwtProviders(
    options: JwtModuleOptionsAsync,
  ): Provider[] {
    if (!options.useClass && !options.useExisting && !options.useFactory) {
      this.logger.error(
        'Error while creating async providers. None of these 3 arguments are provided: useFactory, useClass and useExisting',
      );
      throw new CreateAsyncJwtProvidersError();
    }

    const providers: Provider[] = [
      this.createProviderFromAsyncOptions(options),
    ];
    if (options.useClass) {
      providers.push({
        provide: options.useClass,
        useClass: options.useClass,
      });
    }

    return providers;
  }

  private static createProviderFromAsyncOptions(
    options: JwtModuleOptionsAsync,
  ): Provider {
    return options.useFactory
      ? {
          provide: JWT_OPTIONS,
          useFactory: options.useFactory,
          inject: options.inject || [],
        }
      : {
          provide: JWT_OPTIONS,
          useFactory: async (factoryOptions: JwtModuleFactoryOptions) => {
            return await factoryOptions.createJwtModuleOptions();
          },
          inject: [options.useClass || options.useExisting] as any[],
        };
  }
}
