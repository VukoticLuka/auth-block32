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

@Module({
  providers: [JwtAsyncService],
  exports: [JwtAsyncService],
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
    if (options.useFactory) {
      return [
        this.createProviderFromAsyncOptions(options),
        {
          provide: options.useClass,
          useClass: options.useClass,
        } as any,
      ];
    } else if (options.useClass || options.useExisting) {
      return [this.createProviderFromAsyncOptions(options)];
    } else {
      this.logger.error(
        'Error while creating async providers. None of these 3 arguments are provided: useFactory, useClass and useExisting',
      );
      throw new CreateAsyncJwtProvidersError();
    }
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
            await factoryOptions.createJwtModuleOptions();
          },
          inject: [options.useClass || options.useExisting] as any[],
        };
  }
}
