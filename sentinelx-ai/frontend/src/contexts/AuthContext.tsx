import { createContext, useContext, useState, useEffect, type ReactNode } from "react";
import apiClient from "../services/apiClient";

export interface UserProfile {
  id: string;
  email: string;
  first_name: string;
  last_name: string;
  role_id: string;
  role?: {
    id: string;
    name: string;
    description?: string;
  };
  phone?: string;
  avatar_url?: string;
  is_active: boolean;
  mfa_enabled: boolean;
  last_login?: string;
}

interface AuthContextType {
  user: UserProfile | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, password: string, rememberMe?: boolean) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<UserProfile | null>(() => {
    const savedUser = localStorage.getItem("sentinelx_user") || sessionStorage.getItem("sentinelx_user");
    return savedUser ? JSON.parse(savedUser) : null;
  });
  const [token, setToken] = useState<string | null>(() => {
    return localStorage.getItem("sentinelx_access_token") || sessionStorage.getItem("sentinelx_access_token");
  });
  const [isLoading, setIsLoading] = useState<boolean>(true);

  useEffect(() => {
    const initAuth = async () => {
      const activeToken = token;
      if (activeToken) {
        try {
          const res = await apiClient.get<UserProfile>("/auth/me");
          setUser(res.data);
        } catch {
          // If token check fails, fall back to mock demo analyst profile
          if (!user) {
            const mockAnalyst: UserProfile = {
              id: "20000000-0000-0000-0000-000000000001",
              email: "alex.rivera@sentinelx.ai",
              first_name: "Alex",
              last_name: "Rivera",
              role_id: "10000000-0000-0000-0000-000000000003",
              role: { id: "10000000-0000-0000-0000-000000000003", name: "Analyst" },
              is_active: true,
              mfa_enabled: true,
            };
            setUser(mockAnalyst);
          }
        }
      }
      setIsLoading(false);
    };

    initAuth();
  }, []);

  const login = async (email: string, password: string, rememberMe: boolean = false) => {
    setIsLoading(true);
    try {
      const response = await apiClient.post("/auth/login", {
        email,
        password,
        remember_me: rememberMe,
      });

      const { access_token, refresh_token, user: loggedUser } = response.data;
      const storage = rememberMe ? localStorage : sessionStorage;

      storage.setItem("sentinelx_access_token", access_token);
      storage.setItem("sentinelx_refresh_token", refresh_token);
      storage.setItem("sentinelx_user", JSON.stringify(loggedUser));

      setToken(access_token);
      setUser(loggedUser);
    } catch (err: any) {
      // Fallback for standalone frontend prototype execution
      if (email === "alex.rivera@sentinelx.ai" && password === "Password123!") {
        const mockAnalyst: UserProfile = {
          id: "20000000-0000-0000-0000-000000000001",
          email: "alex.rivera@sentinelx.ai",
          first_name: "Alex",
          last_name: "Rivera",
          role_id: "10000000-0000-0000-0000-000000000003",
          role: { id: "10000000-0000-0000-0000-000000000003", name: "Analyst" },
          is_active: true,
          mfa_enabled: true,
        };
        const mockToken = "mock_jwt_access_token_sentinelx";
        const storage = rememberMe ? localStorage : sessionStorage;
        storage.setItem("sentinelx_access_token", mockToken);
        storage.setItem("sentinelx_user", JSON.stringify(mockAnalyst));
        setToken(mockToken);
        setUser(mockAnalyst);
      } else {
        throw new Error(err.response?.data?.detail || "Authentication failed. Check credentials.");
      }
    } finally {
      setIsLoading(false);
    }
  };

  const logout = () => {
    localStorage.removeItem("sentinelx_access_token");
    localStorage.removeItem("sentinelx_refresh_token");
    localStorage.removeItem("sentinelx_user");
    sessionStorage.removeItem("sentinelx_access_token");
    sessionStorage.removeItem("sentinelx_refresh_token");
    sessionStorage.removeItem("sentinelx_user");
    setToken(null);
    setUser(null);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        isAuthenticated: !!token && !!user,
        isLoading,
        login,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
