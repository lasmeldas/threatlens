import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { api, setUnauthorizedHandler, tokenStore } from './api.js';

const AuthContext = createContext(null);
export const useAuth = () => useContext(AuthContext);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [ready, setReady] = useState(!tokenStore.get());

  useEffect(() => {
    setUnauthorizedHandler(() => setUser(null));
    if (!tokenStore.get()) return;
    api('/me/').then(setUser).catch(() => setUser(null)).finally(() => setReady(true));
  }, []);

  const login = useCallback(async (username, password) => {
    const data = await api('/auth/token/', { method: 'POST', body: { username, password } });
    tokenStore.set(data.token);
    setUser(data.user);
  }, []);

  const logout = useCallback(async () => {
    try { await api('/auth/logout/', { method: 'POST' }); } catch { /* the token is dropped either way */ }
    tokenStore.clear();
    setUser(null);
  }, []);

  const value = useMemo(() => ({ user, ready, login, logout, canEdit: !!user && user.role !== 'viewer' }), [user, ready, login, logout]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
