import { Injectable } from '@nestjs/common';
import { Argon2Options, HashProvider } from './interfaces';
import * as argon2 from 'argon2';

@Injectable()
export class Argon2Provider implements HashProvider {
  // these are recommended values
  private readonly recommendedOptions: Required<Argon2Options> = {
    timeCost: 3,
    memoryCost: 2 ** 16,
    parallelism: 1,
  };
  private options: Required<Argon2Options>;

  constructor(argonOptions: Argon2Options = {}) {
    this.options = {
      ...this.recommendedOptions,
      ...argonOptions,
    };
  }

  async hash(data: string): Promise<string> {
    return argon2.hash(data, this.options);
  }

  async compare(data: string, encryptedData: string): Promise<boolean> {
    return argon2.verify(encryptedData, data);
  }
}
