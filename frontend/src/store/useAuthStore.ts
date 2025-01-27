import { create } from "zustand";
import { persist } from "zustand/middleware";

export interface User {
    id: string;
    email: string;
}

interface AuthState {
    token: string | null;
    user: User | null;
    isAuthenticated: boolean;
    isLoading: boolean;
    _hasHydrated: boolean;
    setHasHydrated: (state: boolean) => void;
    setToken: (token: string | null) => void;
    setUser: (user: User | null) => void;
    setIsAuthenticated: (value: boolean) => void;
    setIsLoading: (value: boolean) => void;
    login: (token: string, user: User) => void;
    logout: () => void;
}

export const useAuthStore = create<AuthState>()(
    persist(
        (set) => ({
            _hasHydrated: false,
            setHasHydrated: (state: boolean) => set({ _hasHydrated: state }),
            token: null,
            user: null,
            isAuthenticated: false,
            isLoading: false,
            setToken: (token) => set({ token }),
            setUser: (user) => set({ user }),
            setIsAuthenticated: (value) => set({ isAuthenticated: value }),
            setIsLoading: (value) => set({ isLoading: value }),
            login: (token, user) =>
                set({
                    token,
                    user,
                    isAuthenticated: true,
                }),
            logout: () =>
                set({
                    token: null,
                    user: null,
                    isAuthenticated: false,
                }),
        }),
        {
            name: "auth-storage",
            skipHydration: true,
        },
    ),
);
