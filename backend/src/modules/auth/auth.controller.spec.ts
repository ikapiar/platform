import { Test, TestingModule } from '@nestjs/testing';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { LoginDto } from './auth.validations';
import { HttpException } from '@nestjs/common';
import { Response } from 'express';

describe('AuthController', () => {
  let controller: AuthController;
  let service: AuthService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        {
          provide: AuthService,
          useValue: {
            localLogin: jest.fn(),
            googleLogin: jest.fn(),
            linkedInLogin: jest.fn(),
          },
        },
      ],
    }).compile();

    controller = module.get<AuthController>(AuthController);
    service = module.get<AuthService>(AuthService);
  });

  describe('localLogin', () => {
    it('should return a token for valid credentials', async () => {
      const loginDto: LoginDto = { email: 'test@example.com', password: 'password' };
      const token = 'valid_token';
      jest.spyOn(service, 'localLogin').mockResolvedValue({ hasError: () => false, get: () => token });

      const res = { cookie: jest.fn() } as unknown as Response;
      const result = await controller.localLogin(loginDto, res);

      expect(result).toEqual({ token });
      expect(res.cookie).toHaveBeenCalledWith('Authorization', `Bearer ${token}`, { httpOnly: true, path: '/' });
    });

    it('should throw an error for invalid credentials', async () => {
      const loginDto: LoginDto = { email: 'test@example.com', password: 'wrongpassword' };
      jest.spyOn(service, 'localLogin').mockResolvedValue({ hasError: () => true, getError: () => new Error('invalid credentials') });

      const res = { cookie: jest.fn() } as unknown as Response;

      await expect(controller.localLogin(loginDto, res)).rejects.toThrow(HttpException);
    });
  });

  describe('googleLogin', () => {
    it('should return a token for valid Google token', async () => {
      const token = 'valid_google_token';
      const jwtToken = 'jwt_token';
      jest.spyOn(service, 'googleLogin').mockResolvedValue({ hasError: () => false, get: () => jwtToken });

      const res = { cookie: jest.fn() } as unknown as Response;
      const result = await controller.googleLogin(token, res);

      expect(result).toEqual({ token: jwtToken });
      expect(res.cookie).toHaveBeenCalledWith('Authorization', `Bearer ${jwtToken}`, { httpOnly: true, path: '/' });
    });

    it('should throw an error for invalid Google token', async () => {
      const token = 'invalid_google_token';
      jest.spyOn(service, 'googleLogin').mockResolvedValue({ hasError: () => true, getError: () => new Error('invalid Google token') });

      const res = { cookie: jest.fn() } as unknown as Response;

      await expect(controller.googleLogin(token, res)).rejects.toThrow(HttpException);
    });
  });

  describe('linkedInLogin', () => {
    it('should return a token for valid LinkedIn token', async () => {
      const token = 'valid_linkedin_token';
      const jwtToken = 'jwt_token';
      jest.spyOn(service, 'linkedInLogin').mockResolvedValue({ hasError: () => false, get: () => jwtToken });

      const res = { cookie: jest.fn() } as unknown as Response;
      const result = await controller.linkedInLogin(token, res);

      expect(result).toEqual({ token: jwtToken });
      expect(res.cookie).toHaveBeenCalledWith('Authorization', `Bearer ${jwtToken}`, { httpOnly: true, path: '/' });
    });

    it('should throw an error for invalid LinkedIn token', async () => {
      const token = 'invalid_linkedin_token';
      jest.spyOn(service, 'linkedInLogin').mockResolvedValue({ hasError: () => true, getError: () => new Error('invalid LinkedIn token') });

      const res = { cookie: jest.fn() } as unknown as Response;

      await expect(controller.linkedInLogin(token, res)).rejects.toThrow(HttpException);
    });
  });
});
