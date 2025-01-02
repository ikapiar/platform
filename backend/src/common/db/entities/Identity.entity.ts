import { Column, Entity, ManyToOne, PrimaryGeneratedColumn } from 'typeorm';
import { User } from './User.entity.ts';

export const IdentityProviders = ['GOOGLE', 'LINKEDIN'] as const;
export type IdentityProvider = (typeof IdentityProviders)[number];

@Entity()
export class Identity {
    @PrimaryGeneratedColumn('uuid')
    id!: string;

    @Column({ enum: IdentityProviders, type: 'enum' })
    provider!: IdentityProvider;

    @Column()
    token!: string;

    @ManyToOne(() => User, (user) => user.identities)
    user!: Promise<User>;

    @Column({ type: 'jsonb', nullable: true })
    metadata?: Record<string, unknown> | undefined | null;

    @Column()
    expires_at!: Date;
}
