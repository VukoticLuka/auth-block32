## Description

A fully typed JWT authentication package for NestJS, built on top of `@nestjs/jwt` and `jsonwebtoken`, with support for access and refresh tokens 🛡️.

The package also includes `guards` for securing your endpoints. You can choose between Async and Sync guards.

The only difference is that the Async guard uses methods from JwtAsyncService, while the Sync guard relies on JwtSyncService.

Both JwtAsyncService and JwtSyncService use [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken) underneath.

This package is inspired by [@nestjs/jwt](https://github.com/nestjs/jwt) and was created to centralize and streamline the entire JWT authentication workflow.

Developers are provided with a comprehensive set of tools required for setting up JWT authentication with minimal additional configuration.

### Features
- Fully typed JWT authentication
- Access and Refresh token support (Async & Sync services)
- Service for managing tokens in headers and cookies
- Async & Sync guards
- Minimal configuration

### Contributing / Motivation 

The primary purpose of this package is to reduce the boilerplate code that developers repeatedly write in projects using JWT authentication.
This project thrives thanks to the open-source community.
If you’d like to contribute, feel free to open **Pull Requests** or **Issues** on [GitHub](https://github.com/VukoticLuka/jwt-block32).

## Installation

```bash
npm install @block32/jwt
```

## Usage

@block32/jwt package comes with multiple services.

Import `JwtModule`:

```typescript
@Module({
    imports: [
        JwtModule.forRoot({
            accessToken: {
                storage: 'header',
                keyOptions: {
                    algorithm: 'HS256',
                    secret: 'access_secret',
                },
            },
            refreshToken: {
                keyOptions: {
                    algorithm: 'HS256',
                    secret: 'refresh_secret',
                },
                cookieOptions: {
                    cookieName: 'RefreshToken',
                    secure: true,
                    path: '/',
                }
            }
        })
    ]
})

export class ExampleModule {}
```
If you want to pass your module options asynchronously (for example, some environment variables), you can use `forRootAsync()` method. In that case you can register module in different ways:

**useClass**

```typescript
JwtModule.forRootAsync({
    useClass: ConfigService
})
```
Here keep in mind that ConfigService needs to return options object that is acceptable by JwtModule. You can check `JwtBlock32Options` type to see what's needed.

**useFactory**

```typescript
JwtModule.forRootAsync({
    imports: [ExampleConfigModule]
    useFactory: async (configService: ConfigService) => ({
        accessToken: {
            storage: configService.get<string>('ACCESS_TOKEN_STORAGE'),
            keyOptions: {
                algorithm: configService.get<string>('ACCESS_TOKEN_ALGORITHM'),
                secret: configService.get<string>('ACCESS_TOKEN_SECRET'),
            }
        }
    })
})
```

**useExisting**

```typescript
JwtModule.forRootAsync({
  imports: [ExampleConfigModule],
  useExisting: ConfigService,
}),
```

### Services

The package includes both **JwtAsyncService** and **JwtSyncService**, enabling support for both asynchronous and synchronous workflows.

### JwtAsyncService example

```typescript
@Injectable()
export class ExampleService {
    constructor(private readonly jwtService: JwtAsyncService) {}
}
```

## License

@block32/jwt is [MIT licensed](LICENSE.md).
