import { ModuleMetadata, Provider, Type } from '@nestjs/common';
import { JwtBlock32Options } from './jwt-block32-options.interface';

export interface JwtModuleFactoryOptions {
  createJwtModuleOptions: () => Promise<JwtBlock32Options> | JwtBlock32Options;
}

export interface JwtModuleOptionsAsync extends Pick<ModuleMetadata, 'imports'> {
  useClass?: Type<JwtModuleFactoryOptions>;
  useFactory?: (
    ...args: any[]
  ) => Promise<JwtBlock32Options> | JwtBlock32Options;
  useExisting?: Type<JwtModuleFactoryOptions>;
  inject?: any[];
  additionalProviders?: Provider[];
}
