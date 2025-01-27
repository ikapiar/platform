import { NestFactory } from '@nestjs/core';
import cookieParser from 'cookie-parser';
import { AppModule } from './app.module';
import { getConfig } from './common/config';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { writeFileSync } from 'fs';
import { ValidationPipe } from '@nestjs/common';
import {
    AuthorizationExceptionFilter,
    BadRequestExceptionFilter,
    EntityNotFoundExceptionFilter,
} from './common/middlewares/errors.ts';
import { initSentry } from './instrument.ts';

async function bootstrap() {
    const app = await NestFactory.create(AppModule, {
        cors: {
            origin: '*',
            methods: '*',
        },
    });
    const appPrefix = getConfig('API_VERSION');
    const appPort = getConfig('PORT');

    app.setGlobalPrefix(appPrefix);
    app.useGlobalPipes(new ValidationPipe({ transform: true }));
    app.useGlobalFilters(
        new EntityNotFoundExceptionFilter(),
        new AuthorizationExceptionFilter(),
        new BadRequestExceptionFilter()
    );
    app.use(cookieParser());

    initSentry();

    // setup swagger
    const swaggerOptions = new DocumentBuilder()
        .setTitle('Platform API')
        .setDescription(getConfig('APP_DESCRIPTION'))
        .setVersion(getConfig('APP_VERSION'))
        .addBearerAuth()
        .build();
    const swaggerDocument = SwaggerModule.createDocument(app, swaggerOptions);
    writeFileSync(
        `${process.cwd()}/swagger.json`,
        JSON.stringify(swaggerDocument, null, 2)
    );
    SwaggerModule.setup(`${appPrefix}/docs`, app, swaggerDocument);

    await app.listen(appPort);
}
bootstrap();
