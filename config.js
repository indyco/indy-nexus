// Frontend configuration
// This file should be generated dynamically in production 
// to inject environment-specific values

// In production, this should be served dynamically by the backend
// or generated during build process
const config = {
    API_BASE_URL: process.env.API_BASE_URL || 'http://localhost:3000/api',
    // Add more configuration as needed
};

// For browser environment, expose on window
if (typeof window !== 'undefined') {
    window.API_BASE_URL = config.API_BASE_URL;
    window.APP_CONFIG = config;
}

// For Node.js environment, export as a module
if (typeof module !== 'undefined' && module.exports) {
    module.exports = config;
}
