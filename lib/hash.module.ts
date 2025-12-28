import { DynamicModule, Module } from '@nestjs/common';
import { HashingOptions } from './interfaces';
import { HASH_PROVIDER } from './constants';
import { BcryptProvider } from './bcrypt-hash.provider';
import { Argon2Provider } from './argon2-hash.provider';

@Module({})
export class HashModule {
  static forRoot(options: HashingOptions): DynamicModule {
    const hashProvider = {
      provide: HASH_PROVIDER,
      useFactory: () => {
        return options.algorithm === 'bcrypt'
          ? new BcryptProvider(options.customSetup)
          : new Argon2Provider(options.customSetup);
      },
    };

    return {
      module: HashModule,
      providers: [hashProvider],
      exports: [HASH_PROVIDER],
    };
  }
}
