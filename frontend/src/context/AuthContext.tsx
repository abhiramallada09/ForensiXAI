import React, { createContext, useContext, useState, useEffect } from 'react';
import { User, UserLogin, UserSignUp } from '../types/forensics';
import {
  getAuthToken,
  setAuthToken,
  loginUser,
  signupUser,
  fetchCurrentUser,
} from '../api/client';

interface AuthContextType {
  user: User | null;
  token: string | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  login: (credentials: UserLogin) => Promise<User>;
  signup: (payload: UserSignUp) => Promise<User>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [token, setTokenState] = useState<string | null>(getAuthToken());
  const [isLoading, setIsLoading] = useState<boolean>(true);

  // Restore authenticated session on mount
  useEffect(() => {
    async function initSession() {
      const storedToken = getAuthToken();
      if (!storedToken) {
        setIsLoading(false);
        return;
      }

      try {
        const currentUser = await fetchCurrentUser();
        setUser(currentUser);
        setTokenState(storedToken);
      } catch (err) {
        console.warn('Session expired or invalid, clearing token.');
        setAuthToken(null);
        setTokenState(null);
        setUser(null);
      } finally {
        setIsLoading(false);
      }
    }

    initSession();
  }, []);

  const login = async (credentials: UserLogin): Promise<User> => {
    setIsLoading(true);
    try {
      const authRes = await loginUser(credentials);
      setUser(authRes.user);
      setTokenState(authRes.access_token);
      return authRes.user;
    } finally {
      setIsLoading(false);
    }
  };

  const signup = async (payload: UserSignUp): Promise<User> => {
    setIsLoading(true);
    try {
      const authRes = await signupUser(payload);
      setUser(authRes.user);
      setTokenState(authRes.access_token);
      return authRes.user;
    } finally {
      setIsLoading(false);
    }
  };

  const logout = () => {
    setAuthToken(null);
    setTokenState(null);
    setUser(null);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        isLoading,
        isAuthenticated: !!user,
        login,
        signup,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export function useAuth(): AuthContextType {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

