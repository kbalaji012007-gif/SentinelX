import axios from "axios";

const API_BASE_URL = import.meta.env.VITE_API_URL || "https://sentinelx-2qer.onrender.com";

/**
 * SentinelX AI – Axios API Client
 * Pre-configured with base URL, auth interceptors, and error handling.
 */
const apiClient = axios.create({
  baseURL: `${API_BASE_URL}/api/v1`,
  timeout: 30000,
  headers: {
    "Content-Type": "application/json",
  },
});

// Request interceptor – attach JWT token
apiClient.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem("sentinelx_access_token");
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor – handle auth errors
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem("sentinelx_access_token");
      window.location.href = "/login";
    }
    return Promise.reject(error);
  }
);

export default apiClient;
