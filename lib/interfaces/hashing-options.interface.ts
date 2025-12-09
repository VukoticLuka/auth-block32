export type BcryptOptions = {
  saltRounds?: number;
};

export type Argon2Options = {
  timeCost?: number;
  memoryCost?: number;
  parallelism?: number;
};

export type HashingOptions =
  | { algorithm: 'bcrypt'; customSetup?: BcryptOptions }
  | { algorithm: 'argon2'; customSetup?: Argon2Options };

export interface HashProvider {
  hash(data: string): Promise<string>;
  compare(data: string, encryptedData: string): Promise<boolean>;
}
