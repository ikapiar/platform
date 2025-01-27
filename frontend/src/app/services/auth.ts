import { type LoginResponse, LoginResponseSchema } from "../types/auth";
import { fetchApi } from "../lib/api";

export const loginUser = async (credentials: {
    email: string;
    password: string;
}): Promise<LoginResponse> => {
    try {
        const response = await fetchApi<LoginResponse>("/v1/login", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify(credentials),
        });

        const data = LoginResponseSchema.parse(await response);

        if (!response.success) {
            throw new Error(data.error);
        }

        return {
            success: true,
            token: data.token,
            user: data.user,
        };
    } catch (error) {
        return {
            success: false,
            error: error instanceof Error ? error.message : "Login failed",
        };
    }
};
