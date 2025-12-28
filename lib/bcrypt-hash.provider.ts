import * as bcrypt from 'bcrypt';
import { BcryptOptions, HashProvider } from './interfaces';
import { SaltRoundsDefault, BCRYPT_OPTIONS } from './constants';
import { Inject, Logger, Optional } from '@nestjs/common';

export class BcryptProvider implements HashProvider {
  private readonly logger = new Logger(BcryptProvider.name);

  constructor(
    @Optional()
    @Inject(BCRYPT_OPTIONS)
    private readonly options: BcryptOptions = {},
  ) {}

  async hash(data: string): Promise<string> {
    const saltRounds = this.getBcryptOptions(this.options);
    return bcrypt.hash(data, saltRounds);
  }

  async compare(data: string, encryptedData: string): Promise<boolean> {
    return bcrypt.compare(data, encryptedData);
  }

  private getBcryptOptions(options?: BcryptOptions): number {
    return options?.saltRounds ?? SaltRoundsDefault;
  }
}
