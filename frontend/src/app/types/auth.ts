import { z } from "zod";

export type LoginResponse = z.infer<typeof LoginResponseSchema>;
export type User = z.infer<typeof UserSchema>;

export const UserSchema = z.object({
    id: z.string(),
    email: z.string(),
    name: z.string(),
    role: z.string(),
    createdAt: z.string(),
    updatedAt: z.string(),
});

export const LoginResponseSchema = z.object({
    success: z.boolean(),
    token: z.string().optional(),
    error: z.string().optional(),
    user: UserSchema.optional(),
});

export interface LoginCredentials {
    email: string;
    password: string;
}
