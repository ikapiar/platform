import { Injectable } from '@nestjs/common';
import { getConfig, PRIVATE_KEY } from '../../common/config';
import { scryptSync } from 'crypto';
import { SignJWT, importPKCS8 } from 'jose';
import { Perhaps } from '../../common/utils/Perhaps.ts';
import { Repository } from 'typeorm';
import { User } from '../../common/db/entities/User.entity.ts';
import { InjectRepository } from '@nestjs/typeorm';
import type { RoleName } from '../../common/db/entities/Role.entity.ts';

@Injectable()
export class AuthService {
    constructor(
        @InjectRepository(User)
        private readonly userRepo: Repository<User>
    ) {}

    async localLogin(
        email: string,
        password: string
    ): Promise<Perhaps<string>> {
        const foundUser = await this.userRepo.findOne({ where: { email } });
        if (!foundUser) {
            return Perhaps.OfError(new Error('invalid credentials'));
        }
        if (foundUser.state !== 'active') {
            return Perhaps.OfError(
                new Error('user is inactive. state: ' + foundUser.state)
            );
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

    async googleLogin() {}

    async linkedInLogin() {}
}

type UserToken = {
    id: string;
    email: string;
    roles: RoleName[];
};
