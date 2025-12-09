import * as bcrypt from 'bcrypt';
import { BcryptOptions, HashProvider } from './interfaces';
import { Injectable } from '@nestjs/common';

@Injectable()
export class BcryptProvider implements HashProvider {
  private saltRounds: number;

  constructor(options: BcryptOptions = {}) {
    if (options.saltRounds) {
      this.saltRounds = options.saltRounds;
    } else {
      this.saltRounds = 10;
    }
  }

  async hash(data: string): Promise<string> {
    return bcrypt.hash(data, this.saltRounds);
  }

  async compare(data: string, encryptedData: string): Promise<boolean> {
    return bcrypt.compare(data, encryptedData);
  }
}
