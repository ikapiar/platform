import { SetMetadata } from '@nestjs/common';
import type { Role } from '../../common/db/entities/User.entity.ts';

export const ROLES_KEY = 'roles';
export const Roles = (...roles: Role[]) => SetMetadata(ROLES_KEY, roles);
