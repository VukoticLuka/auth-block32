import { JWT_OPTIONS } from './constants';
import { JwtBlock32Options } from './interfaces';

export function createJwtBlock32Provider(options: JwtBlock32Options): any[] {
  return [
    {
      provide: JWT_OPTIONS,
      useValue: options || {},
    },
  ];
}
