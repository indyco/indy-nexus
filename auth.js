// Authentication JavaScript
// API_BASE should be configured in your deployment environment
// For local development, this defaults to localhost:3000
const API_BASE = window.API_BASE_URL || 'http://localhost:3000/api';

// Utility function to show messages
function showMessage(elementId, message, isError = true) {
    const element = document.getElementById(elementId);
    if (element) {
        element.textContent = message;
        element.className = isError ? 'error-message show' : 'success-message show';
        setTimeout(() => {
            element.className = isError ? 'error-message' : 'success-message';
        }, 5000);
    }
}

// Password validation
function validatePasswordStrength(password) {
    // Silently check for English characters only (for security, not shown to user)
    const englishOnly = /^[A-Za-z0-9!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?\s]+$/.test(password);
    
    const requirements = {
        length: password.length >= 20 && password.length <= 84,
        englishOnly: englishOnly, // Hidden from user display
        upper: /[A-Z]/.test(password),
        lower: /[a-z]/.test(password),
        number: /\d/.test(password),
        special: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)
    };
    
    return requirements;
}

// Validate username - silently check for English characters
function validateUsername(username) {
    // Check format (shown to user)
    const validFormat = /^[a-zA-Z0-9_]{3,30}$/.test(username);
    // Silent ASCII check (not revealed to user)
    const asciiOnly = /^[\x00-\x7F]*$/.test(username);
    
    return { validFormat, asciiOnly };
}

// Update password requirements display (for registration)
function updatePasswordRequirements(password) {
    const requirements = validatePasswordStrength(password);
    
    // Update requirement indicators (deliberately excluding English check)
    const lengthCheck = document.getElementById('lengthCheck');
    const upperCheck = document.getElementById('upperCheck');
    const lowerCheck = document.getElementById('lowerCheck');
    const numberCheck = document.getElementById('numberCheck');
    const specialCheck = document.getElementById('specialCheck');
    
    if (lengthCheck) {
        lengthCheck.textContent = (requirements.length ? '✓' : '✗') + ' 20-84 characters';
        lengthCheck.className = 'requirement ' + (requirements.length ? 'valid' : 'invalid');
    }
    if (upperCheck) {
        upperCheck.textContent = (requirements.upper ? '✓' : '✗') + ' At least one uppercase letter';
        upperCheck.className = 'requirement ' + (requirements.upper ? 'valid' : 'invalid');
    }
    if (lowerCheck) {
        lowerCheck.textContent = (requirements.lower ? '✓' : '✗') + ' At least one lowercase letter';
        lowerCheck.className = 'requirement ' + (requirements.lower ? 'valid' : 'invalid');
    }
    if (numberCheck) {
        numberCheck.textContent = (requirements.number ? '✓' : '✗') + ' At least one number';
        numberCheck.className = 'requirement ' + (requirements.number ? 'valid' : 'invalid');
    }
    if (specialCheck) {
        specialCheck.textContent = (requirements.special ? '✓' : '✗') + ' At least one special character';
        specialCheck.className = 'requirement ' + (requirements.special ? 'valid' : 'invalid');
    }
    
    // Update password strength indicator
    const strengthIndicator = document.getElementById('passwordStrength');
    if (strengthIndicator) {
        const allValid = Object.values(requirements).every(v => v);
        const validCount = Object.values(requirements).filter(v => v).length;
        
        if (validCount === 0) {
            strengthIndicator.className = 'password-strength';
        } else if (validCount <= 2) {
            strengthIndicator.className = 'password-strength weak';
        } else if (validCount <= 4) {
            strengthIndicator.className = 'password-strength medium';
        } else if (allValid) {
            strengthIndicator.className = 'password-strength strong';
        }
    }
}

// Store authentication token
function setAuthToken(token) {
    localStorage.setItem('authToken', token);
}

// Get authentication token
function getAuthToken() {
    return localStorage.getItem('authToken');
}

// Remove authentication token
function removeAuthToken() {
    localStorage.removeItem('authToken');
}

// Check if user is logged in
function isLoggedIn() {
    return !!getAuthToken();
}

// Login form handler
const loginForm = document.getElementById('loginForm');
if (loginForm) {
    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        
        // Basic validation
        if (password.length < 20 || password.length > 84) {
            showMessage('errorMessage', 'Password must be between 20 and 84 characters');
            return;
        }
        
        // Silent security checks (don't reveal to potential attackers)
        const usernameCheck = validateUsername(username);
        const passwordEnglishOnly = /^[A-Za-z0-9!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?\s]+$/.test(password);
        
        // If non-English characters detected, show generic error (obfuscation)
        if (!usernameCheck.asciiOnly || !passwordEnglishOnly) {
            // Generic error - don't reveal the real reason
            showMessage('errorMessage', 'Invalid credentials');
            // Optional: Log this as potential attack
            console.warn('Non-English character attempt detected');
            return;
        }
        
        // Check username format (this error is OK to show)
        if (!usernameCheck.validFormat) {
            showMessage('errorMessage', 'Username must be 3-30 characters, alphanumeric and underscore only');
            return;
        }
        
        try {
            const response = await fetch(`${API_BASE}/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, password })
            });
            
            const data = await response.json();
            
            if (response.ok) {
                // Store token
                setAuthToken(data.token);
                
                // Show success message
                showMessage('successMessage', 'Login successful! Redirecting...', false);
                
                // Redirect after delay
                setTimeout(() => {
                    window.location.href = '/dashboard.html';
                }, 1500);
            } else if (response.status === 403 && data.awaiting_approval) {
                // Special handling for awaiting approval
                showMessage('errorMessage', 'Awaiting approval. Please contact the administrator.');
            } else {
                showMessage('errorMessage', data.error || 'Login failed');
            }
        } catch (error) {
            console.error('Login error:', error);
            showMessage('errorMessage', 'Connection error. Please try again.');
        }
    });
}

// Registration form handler
const registerForm = document.getElementById('registerForm');
if (registerForm) {
    // Password input event listener
    const passwordInput = document.getElementById('password');
    if (passwordInput) {
        passwordInput.addEventListener('input', (e) => {
            updatePasswordRequirements(e.target.value);
        });
    }
    
    registerForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const username = document.getElementById('username').value;
        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;
        const confirmPassword = document.getElementById('confirmPassword').value;
        
        // Validate passwords match
        if (password !== confirmPassword) {
            showMessage('errorMessage', 'Passwords do not match');
            return;
        }
        
        // Validate password requirements
        const requirements = validatePasswordStrength(password);
        const usernameCheck = validateUsername(username);
        
        // Silent check for non-English characters (security feature)
        if (!requirements.englishOnly || !usernameCheck.asciiOnly) {
            // Show generic error that doesn't reveal our security check
            // This confuses attackers using non-English characters
            showMessage('errorMessage', 'Registration failed. Please check your information.');
            console.warn('Non-English character registration attempt');
            // Silently fail - attacker won't know why
            return;
        }
        
        // Check visible requirements (OK to show these)
        if (!usernameCheck.validFormat) {
            showMessage('errorMessage', 'Username must be 3-30 characters, alphanumeric and underscore only');
            return;
        }
        
        // Check other password requirements (excluding englishOnly)
        const visibleRequirements = {
            length: requirements.length,
            upper: requirements.upper,
            lower: requirements.lower,
            number: requirements.number,
            special: requirements.special
        };
        
        if (!Object.values(visibleRequirements).every(v => v)) {
            showMessage('errorMessage', 'Password does not meet all requirements');
            return;
        }
        
        try {
            const response = await fetch(`${API_BASE}/register`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, email, password })
            });
            
            const data = await response.json();
            
            if (response.ok) {
                // Don't store token or redirect for new registrations
                // They need approval first
                showMessage('successMessage', 'Registration successful! Your account is pending approval. You will be able to login once approved.', false);
                
                // Redirect to login page after delay
                setTimeout(() => {
                    window.location.href = '/login.html';
                }, 3000);
            } else {
                showMessage('errorMessage', data.error || 'Registration failed');
            }
        } catch (error) {
            console.error('Registration error:', error);
            showMessage('errorMessage', 'Connection error. Please try again.');
        }
    });
}

// Logout function
async function logout() {
    const token = getAuthToken();
    
    if (token) {
        try {
            await fetch(`${API_BASE}/logout`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
        } catch (error) {
            console.error('Logout error:', error);
        }
    }
    
    removeAuthToken();
    window.location.href = '/login.html';
}

// Check authentication status
async function checkAuth() {
    const token = getAuthToken();
    
    if (!token) {
        return false;
    }
    
    try {
        const response = await fetch(`${API_BASE}/profile`, {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        
        if (response.ok) {
            return true;
        } else {
            removeAuthToken();
            return false;
        }
    } catch (error) {
        console.error('Auth check error:', error);
        return false;
    }
}

// Protected page check
if (window.location.pathname.includes('dashboard')) {
    checkAuth().then(isAuthenticated => {
        if (!isAuthenticated) {
            window.location.href = '/login.html';
        }
    });
}