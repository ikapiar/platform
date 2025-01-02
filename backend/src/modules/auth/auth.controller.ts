import { Body, Controller, HttpException, Post, Res } from '@nestjs/common';
import { ApiBody, ApiOperation } from '@nestjs/swagger';
import { LoginDto } from './auth.validations.ts';
import { AuthService } from './auth.service.ts';
import type { Response } from 'express';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) {}

    @Post('login')
    @ApiOperation({
        summary:
            'Login with email and password. Returns set-cookie JWT token with user info (id, email, roles).',
    })
    @ApiBody({ type: LoginDto })
    async localLogin(
        @Body() loginDto: LoginDto,
        @Res({ passthrough: true }) res: Response
    ) {
        const perhapsToken = await this.authService.localLogin(
            loginDto.email,
            loginDto.password
        );
        if (perhapsToken.hasError()) {
            throw new HttpException(perhapsToken.getError().message, 403);
        }
        const token = perhapsToken.get();
        res.cookie('Authorization', `Bearer ${token}`, {
            httpOnly: true,
            path: '/',
        });
        return { token };
    }

    @Post('google-login')
    @ApiOperation({
        summary:
            'Login with Google. Returns set-cookie JWT token with user info (id, email, roles).',
    })
    async googleLogin(
        @Body('token') token: string,
        @Res({ passthrough: true }) res: Response
    ) {
        const perhapsToken = await this.authService.googleLogin(token);
        if (perhapsToken.hasError()) {
            throw new HttpException(perhapsToken.getError().message, 403);
        }
        const jwtToken = perhapsToken.get();
        res.cookie('Authorization', `Bearer ${jwtToken}`, {
            httpOnly: true,
            path: '/',
        });
        return { token: jwtToken };
    }

    @Post('linkedin-login')
    @ApiOperation({
        summary:
            'Login with LinkedIn. Returns set-cookie JWT token with user info (id, email, roles).',
    })
    async linkedInLogin(
        @Body('token') token: string,
        @Res({ passthrough: true }) res: Response
    ) {
        const perhapsToken = await this.authService.linkedInLogin(token);
        if (perhapsToken.hasError()) {
            throw new HttpException(perhapsToken.getError().message, 403);
        }
        const jwtToken = perhapsToken.get();
        res.cookie('Authorization', `Bearer ${jwtToken}`, {
            httpOnly: true,
            path: '/',
        });
        return { token: jwtToken };
    }

    @Post('verify')
    @ApiOperation({
        summary: 'Verify JWT token. Returns the token payload if valid.',
    })
    async verifyToken(@Body('token') token: string) {
        const perhapsPayload = await this.authService.verifyToken(token);
        if (perhapsPayload.hasError()) {
            throw new HttpException(perhapsPayload.getError().message, 403);
        }
        return { payload: perhapsPayload.get() };
    }
}
