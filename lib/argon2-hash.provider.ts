import * as argon2 from 'argon2';
import { Argon2Options, HashProvider } from './interfaces';
import { ARGON2_OPTIONS, Argon2Default } from './constants';
import { Inject, Logger, Optional } from '@nestjs/common';

export class Argon2Provider implements HashProvider {
  private readonly logger = new Logger(Argon2Provider.name);

  constructor(
    @Optional()
    @Inject(ARGON2_OPTIONS)
    private readonly argon2Options: Argon2Options = {},
  ) {}

  async hash(data: string): Promise<string> {
    const options = this.getArgon2Options(this.argon2Options);
    return argon2.hash(data, options);
  }

  async compare(data: string, encryptedData: string): Promise<boolean> {
    return argon2.verify(encryptedData, data);
  }

  private getArgon2Options(options?: Argon2Options): Argon2Options {
    return {
      ...Argon2Default,
      ...options,
    };
  }
}
