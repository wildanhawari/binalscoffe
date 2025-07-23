import secureLocalStorage from "react-secure-storage";
import axios from "axios";

// Base configuration
axios.defaults.baseURL = import.meta.env.VITE_API_URL;
axios.defaults.timeout = import.meta.env.VITE_API_TIMEOUT || 30000;
axios.defaults.headers.common["Content-Type"] = "application/json";

const api = axios.create();

// Flag untuk mencegah multiple refresh calls
let isRefreshing = false;
let failedQueue = [];

// Process queue after refresh
const processQueue = (error, token = null) => {
  failedQueue.forEach(prom => {
    if (error) {
      prom.reject(error);
    } else {
      prom.resolve(token);
    }
  });
  
  failedQueue = [];
};

// Request interceptor - attach token
api.interceptors.request.use(
  (request) => {
    const token = secureLocalStorage.getItem("acessToken"); // Fix typo: accessToken
    if (token) {
      request.headers["Authorization"] = `Bearer ${token}`;
    }
    return request;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Enhanced refresh token logic
const refreshAuthLogic = async () => {
  try {
    const refreshToken = secureLocalStorage.getItem("refreshToken");
    
    if (!refreshToken) {
      throw new Error("No refresh token available");
    }

    console.log("🔄 Refreshing access token...");
    
    const response = await axios.request({
      url: `/api/users/refresh`,
      method: "GET",
      headers: {
        "Authorization": `Bearer ${refreshToken}`,
        "Content-Type": "application/json"
      },
      baseURL: import.meta.env.VITE_API_URL
    });

    const { acessToken, refreshToken: newRefreshToken, result } = response.data;
    
    // Update tokens in storage
    secureLocalStorage.setItem("acessToken", acessToken);
    secureLocalStorage.setItem("refreshToken", newRefreshToken);
    secureLocalStorage.setItem("user", result);
    
    console.log("✅ Access token refreshed successfully");
    
    return acessToken;
    
  } catch (error) {
    console.error("❌ Refresh token failed:", error.message);
    
    // Clear all auth data
    secureLocalStorage.removeItem("acessToken");
    secureLocalStorage.removeItem("refreshToken");
    secureLocalStorage.removeItem("user");
    
    // Redirect to login
    window.location.href = "/login";
    
    throw error;
  }
};

// Response interceptor - handle token refresh
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    
    // Check if error is 401 (Unauthorized) and request hasn't been retried
    if (error.response?.status === 401 && !originalRequest._retry) {
      
      if (isRefreshing) {
        // If already refreshing, queue the request
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject });
        }).then(token => {
          originalRequest.headers['Authorization'] = `Bearer ${token}`;
          return api(originalRequest);
        }).catch(err => {
          return Promise.reject(err);
        });
      }

      originalRequest._retry = true;
      isRefreshing = true;

      try {
        const newToken = await refreshAuthLogic();
        
        // Update the original request with new token
        originalRequest.headers['Authorization'] = `Bearer ${newToken}`;
        
        // Process queued requests
        processQueue(null, newToken);
        
        // Retry original request
        return api(originalRequest);
        
      } catch (refreshError) {
        processQueue(refreshError, null);
        return Promise.reject(refreshError);
      } finally {
        isRefreshing = false;
      }
    }
    
    return Promise.reject(error);
  }
);

export const axiosInstance = api;

// Helper function to check token expiry
export const isTokenExpired = (token) => {
  if (!token) return true;
  
  try {
    const payload = JSON.parse(atob(token.split('.')[1]));
    const currentTime = Date.now() / 1000;
    return payload.exp < currentTime;
  } catch (error) {
    return true;
  }
};

// Helper function to manually refresh token
export const refreshToken = async () => {
  try {
    return await refreshAuthLogic();
  } catch (error) {
    console.error("Manual token refresh failed:", error);
    throw error;
  }
};

// Helper function to logout
export const logout = () => {
  secureLocalStorage.removeItem("acessToken");
  secureLocalStorage.removeItem("refreshToken"); 
  secureLocalStorage.removeItem("user");
  window.location.href = "/login";
};