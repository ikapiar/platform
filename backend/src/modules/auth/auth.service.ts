import { Injectable } from '@nestjs/common';
import { getConfig, PRIVATE_KEY } from '../../common/config';
import { scryptSync } from 'crypto';
import { SignJWT, importPKCS8 } from 'jose';
import { Perhaps } from '../../common/utils/Perhaps.ts';
import { Repository } from 'typeorm';
import { User } from '../../common/db/entities/User.entity.ts';
import { InjectRepository } from '@nestjs/typeorm';
import type { RoleName } from '../../common/db/entities/Role.entity.ts';
import { Identity, IdentityProvider } from '../../common/db/entities/Identity.entity.ts';

@Injectable()
export class AuthService {
    constructor(
        @InjectRepository(User)
        private readonly userRepo: Repository<User>,
        @InjectRepository(Identity)
        private readonly identityRepo: Repository<Identity>
    ) {}

    async localLogin(
        email: string,
        password: string
    ): Promise<Perhaps<string>> {
        const foundUser = await this.userRepo.findOne({ where: { email }, relations: ['identities'] });
        if (!foundUser) {
            return Perhaps.OfError(new Error('invalid credentials'));
        }
        const hashLength = parseInt(getConfig('PASSWORD_HASHED_LENGTH'));
        const salt = getConfig('PASSWORD_SALT');
        const hashedPassword = scryptSync(password, salt, hashLength).toString(
            'hex'
        );
        const isPasswordMatch = foundUser.password_hash === hashedPassword;
        if (!isPasswordMatch) {
            return Perhaps.OfError(new Error('invalid credentials'));
        }
        const roles = await foundUser.roles;
        const tokenBody: UserToken = {
            id: foundUser.id,
            email: foundUser.email,
            roles: roles.map((role) => role.name),
        };
        const alg = getConfig('JWT_ALGORITHM');
        const privateKey = await importPKCS8(PRIVATE_KEY.toString(), alg);
        const token = await new SignJWT(tokenBody)
            .setProtectedHeader({ alg })
            .setIssuedAt()
            .setExpirationTime(getConfig('JWT_EXPIRES_IN'))
            .sign(privateKey);
        return Perhaps.Of(token);
    }

    async googleLogin(token: string): Promise<Perhaps<string>> {
        const googleUser = await this.verifyGoogleToken(token);
        if (!googleUser) {
            return Perhaps.OfError(new Error('invalid Google token'));
        }
        let user = await this.userRepo.findOne({ where: { email: googleUser.email }, relations: ['identities'] });
        if (!user) {
            user = this.userRepo.create({ email: googleUser.email, password_hash: '' });
            await this.userRepo.save(user);
        }
        const identity = this.identityRepo.create({
            provider: IdentityProvider.GOOGLE,
            token,
            user: Promise.resolve(user),
            metadata: googleUser,
            expires_at: new Date(Date.now() + 3600 * 1000),
        });
        await this.identityRepo.save(identity);
        const roles = await user.roles;
        const tokenBody: UserToken = {
            id: user.id,
            email: user.email,
            roles: roles.map((role) => role.name),
        };
        const alg = getConfig('JWT_ALGORITHM');
        const privateKey = await importPKCS8(PRIVATE_KEY.toString(), alg);
        const jwtToken = await new SignJWT(tokenBody)
            .setProtectedHeader({ alg })
            .setIssuedAt()
            .setExpirationTime(getConfig('JWT_EXPIRES_IN'))
            .sign(privateKey);
        return Perhaps.Of(jwtToken);
    }

    async linkedInLogin(token: string): Promise<Perhaps<string>> {
        const linkedInUser = await this.verifyLinkedInToken(token);
        if (!linkedInUser) {
            return Perhaps.OfError(new Error('invalid LinkedIn token'));
        }
        let user = await this.userRepo.findOne({ where: { email: linkedInUser.email }, relations: ['identities'] });
        if (!user) {
            user = this.userRepo.create({ email: linkedInUser.email, password_hash: '' });
            await this.userRepo.save(user);
        }
        const identity = this.identityRepo.create({
            provider: IdentityProvider.LINKEDIN,
            token,
            user: Promise.resolve(user),
            metadata: linkedInUser,
            expires_at: new Date(Date.now() + 3600 * 1000),
        });
        await this.identityRepo.save(identity);
        const roles = await user.roles;
        const tokenBody: UserToken = {
            id: user.id,
            email: user.email,
            roles: roles.map((role) => role.name),
        };
        const alg = getConfig('JWT_ALGORITHM');
        const privateKey = await importPKCS8(PRIVATE_KEY.toString(), alg);
        const jwtToken = await new SignJWT(tokenBody)
            .setProtectedHeader({ alg })
            .setIssuedAt()
            .setExpirationTime(getConfig('JWT_EXPIRES_IN'))
            .sign(privateKey);
        return Perhaps.Of(jwtToken);
    }

    private async verifyGoogleToken(token: string): Promise<any> {
        // Implement Google token verification logic here
    }

    private async verifyLinkedInToken(token: string): Promise<any> {
        // Implement LinkedIn token verification logic here
    }
}

type UserToken = {
    id: string;
    email: string;
    roles: RoleName[];
};
