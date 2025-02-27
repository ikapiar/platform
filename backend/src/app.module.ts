import { Logger, Module, type OnApplicationBootstrap } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { generateOrmOptions, getConfig } from './common/config';
import { seedDB } from './common/db/seeding.ts';
import { AuthModule } from './modules/auth/auth.module.ts';
import { UserModule } from './modules/user/user.module.ts';
import { APP_FILTER, APP_GUARD } from '@nestjs/core';
import { AuthMiddleware } from './common/middlewares/auth.ts';
import { SentryGlobalFilter, SentryModule } from '@sentry/nestjs/setup';

@Module({
    imports: [
        SentryModule.forRoot(),
        TypeOrmModule.forRootAsync(generateOrmOptions()),
        AuthModule,
        UserModule,
    ],
    controllers: [],
    providers: [
        {
            provide: APP_GUARD,
            useClass: AuthMiddleware,
        },
        {
            provide: APP_FILTER,
            useClass: SentryGlobalFilter,
        },
    ],
})
export class AppModule implements OnApplicationBootstrap {
    private readonly logger = new Logger(AppModule.name);
    async onApplicationBootstrap() {
        if (getConfig('APP_ENV') === 'development') {
            this.logger.log('App is running in development mode');
            await seedDB();
        }
    }
}
