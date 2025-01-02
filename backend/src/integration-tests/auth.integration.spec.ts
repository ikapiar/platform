import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from '../modules/auth/auth.service';
import { getRepositoryToken } from '@nestjs/typeorm';
import { User } from '../common/db/entities/User.entity';
import { Identity } from '../common/db/entities/Identity.entity';
import { Repository } from 'typeorm';
import { scryptSync } from 'crypto';
import { getConfig } from '../common/config';
import { Perhaps } from '../common/utils/Perhaps';
import { GenericContainer, StartedTestContainer } from 'testcontainers';

describe('AuthService Integration Tests', () => {
  let service: AuthService;
  let userRepository: Repository<User>;
  let identityRepository: Repository<Identity>;
  let postgresContainer: StartedTestContainer;

  beforeAll(async () => {
    postgresContainer = await new GenericContainer('postgres')
      .withEnv('POSTGRES_USER', 'test')
      .withEnv('POSTGRES_PASSWORD', 'test')
      .withEnv('POSTGRES_DB', 'test')
      .withExposedPorts(5432)
      .start();

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

  afterAll(async () => {
    await postgresContainer.stop();
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
      await userRepository.save(user);

      const result = await service.localLogin(email, password);

      expect(result.hasError()).toBe(false);
      expect(result.get()).toBeDefined();
    });

    it('should return an error for invalid credentials', async () => {
      const email = 'test@example.com';
      const password = 'wrongpassword';

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
      await userRepository.save(user);
      const identity = new Identity();
      identity.provider = 'GOOGLE';
      identity.token = token;
      identity.user = Promise.resolve(user);
      identity.expires_at = new Date(Date.now() + 3600 * 1000);
      await identityRepository.save(identity);

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
      await userRepository.save(user);
      const identity = new Identity();
      identity.provider = 'LINKEDIN';
      identity.token = token;
      identity.user = Promise.resolve(user);
      identity.expires_at = new Date(Date.now() + 3600 * 1000);
      await identityRepository.save(identity);

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
