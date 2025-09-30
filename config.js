// Frontend configuration
// This file should be generated dynamically in production 
// to inject environment-specific values

// In production, this should be served dynamically by the backend
// or generated during build process
window.API_BASE_URL = window.API_BASE_URL || 'http://localhost:3000/api';

// Add any other frontend configuration here
window.APP_CONFIG = {
    API_BASE_URL: window.API_BASE_URL,
    // Add more configuration as needed
};