import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { getRepositoryToken } from '@nestjs/typeorm';
import { User } from '../../common/db/entities/User.entity';
import { Identity } from '../../common/db/entities/Identity.entity';
import { Repository } from 'typeorm';
import { scryptSync } from 'crypto';
import { getConfig } from '../../common/config';
import { Perhaps } from '../../common/utils/Perhaps';

describe('AuthService', () => {
  let service: AuthService;
  let userRepository: Repository<User>;
  let identityRepository: Repository<Identity>;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: getRepositoryToken(User),
          useClass: Repository,
        },
        {
          provide: getRepositoryToken(Identity),
          useClass: Repository,
        },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    userRepository = module.get<Repository<User>>(getRepositoryToken(User));
    identityRepository = module.get<Repository<Identity>>(getRepositoryToken(Identity));
  });

  describe('localLogin', () => {
    it('should return a token for valid credentials', async () => {
      const email = 'test@example.com';
      const password = 'password';
      const hashedPassword = scryptSync(password, getConfig('PASSWORD_SALT'), Number(getConfig('PASSWORD_HASHED_LENGTH'))).toString('hex');
      const user = new User();
      user.email = email;
      user.password_hash = hashedPassword;
      user.roles = Promise.resolve([]);
      jest.spyOn(userRepository, 'findOne').mockResolvedValue(user);

      const result = await service.localLogin(email, password);

      expect(result.hasError()).toBe(false);
      expect(result.get()).toBeDefined();
    });

    it('should return an error for invalid credentials', async () => {
      const email = 'test@example.com';
      const password = 'wrongpassword';
      jest.spyOn(userRepository, 'findOne').mockResolvedValue(null);

      const result = await service.localLogin(email, password);

      expect(result.hasError()).toBe(true);
      expect(result.getError().message).toBe('invalid credentials');
    });
  });

  describe('googleLogin', () => {
    it('should return a token for valid Google token', async () => {
      const token = 'valid_google_token';
      const googleUser = { email: 'test@example.com' };
      jest.spyOn(service, 'verifyGoogleToken').mockResolvedValue(googleUser);
      const user = new User();
      user.email = googleUser.email;
      user.password_hash = '';
      user.roles = Promise.resolve([]);
      jest.spyOn(userRepository, 'findOne').mockResolvedValue(user);
      jest.spyOn(identityRepository, 'save').mockResolvedValue(new Identity());

      const result = await service.googleLogin(token);

      expect(result.hasError()).toBe(false);
      expect(result.get()).toBeDefined();
    });

    it('should return an error for invalid Google token', async () => {
      const token = 'invalid_google_token';
      jest.spyOn(service, 'verifyGoogleToken').mockResolvedValue(null);

      const result = await service.googleLogin(token);

      expect(result.hasError()).toBe(true);
      expect(result.getError().message).toBe('invalid Google token');
    });
  });

  describe('linkedInLogin', () => {
    it('should return a token for valid LinkedIn token', async () => {
      const token = 'valid_linkedin_token';
      const linkedInUser = { email: 'test@example.com' };
      jest.spyOn(service, 'verifyLinkedInToken').mockResolvedValue(linkedInUser);
      const user = new User();
      user.email = linkedInUser.email;
      user.password_hash = '';
      user.roles = Promise.resolve([]);
      jest.spyOn(userRepository, 'findOne').mockResolvedValue(user);
      jest.spyOn(identityRepository, 'save').mockResolvedValue(new Identity());

      const result = await service.linkedInLogin(token);

      expect(result.hasError()).toBe(false);
      expect(result.get()).toBeDefined();
    });

    it('should return an error for invalid LinkedIn token', async () => {
      const token = 'invalid_linkedin_token';
      jest.spyOn(service, 'verifyLinkedInToken').mockResolvedValue(null);

      const result = await service.linkedInLogin(token);

      expect(result.hasError()).toBe(true);
      expect(result.getError().message).toBe('invalid LinkedIn token');
    });
  });
});
