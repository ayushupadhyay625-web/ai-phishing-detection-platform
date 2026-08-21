import {
  createContext,
  useContext,
  useEffect,
  useState,
} from "react";

import api from "../api/axios";


const AuthContext = createContext(null);


export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(() => {
    const savedUser = localStorage.getItem(
      "phishguard_user"
    );

    return savedUser
      ? JSON.parse(savedUser)
      : null;
  });

  const [loading, setLoading] = useState(true);


  const saveAuthentication = (
    token,
    authenticatedUser
  ) => {
    localStorage.setItem(
      "phishguard_token",
      token
    );

    localStorage.setItem(
      "phishguard_user",
      JSON.stringify(authenticatedUser)
    );

    setUser(authenticatedUser);
  };


  const login = async (email, password) => {
    const response = await api.post(
      "/auth/login",
      {
        email,
        password,
      }
    );

    saveAuthentication(
      response.data.token,
      response.data.user
    );

    return response.data;
  };


  const register = async (
    name,
    email,
    password
  ) => {
    const response = await api.post(
      "/auth/register",
      {
        name,
        email,
        password,
      }
    );

    saveAuthentication(
      response.data.token,
      response.data.user
    );

    return response.data;
  };


  const logout = () => {
    localStorage.removeItem(
      "phishguard_token"
    );

    localStorage.removeItem(
      "phishguard_user"
    );

    setUser(null);
  };


  const loadUserProfile = async () => {
    const token = localStorage.getItem(
      "phishguard_token"
    );

    if (!token) {
      setLoading(false);
      return;
    }

    try {
      const response = await api.get(
        "/auth/profile"
      );

      const profile = response.data.user;

      localStorage.setItem(
        "phishguard_user",
        JSON.stringify(profile)
      );

      setUser(profile);
    } catch (error) {
      logout();
    } finally {
      setLoading(false);
    }
  };


  useEffect(() => {
    loadUserProfile();
  }, []);


  const value = {
    user,
    loading,
    isAuthenticated: Boolean(user),
    login,
    register,
    logout,
  };


  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};


export const useAuth = () => {
  const context = useContext(AuthContext);

  if (!context) {
    throw new Error(
      "useAuth must be used inside AuthProvider"
    );
  }

  return context;
};