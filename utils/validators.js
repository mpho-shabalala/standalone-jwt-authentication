const AppError = require('./appError'); // Adjust path if needed

const validators = {
  validateNewUser: ({ username, email, password }) => {
    if (!username || !email || !password) {
      throw new AppError(
        'Missing required fields',
        400,
        'MISSING_FIELDS'
      );
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      throw new AppError(
        'Invalid email format',
        400,
        'INVALID_EMAIL_FORMAT'
      );
    }

    if (password.length < 8) {
      throw new AppError(
        'Password too short (minimum 8 characters)',
        400,
        'WEAK_PASSWORD'
      );
    }
  },

  validateLoginUser: ({ username, password }) => {
    if (!username || !password) {
      throw new AppError(
        'Username and password are required',
        400,
        'MISSING_CREDENTIALS'
      );
    }
  },

  validateEmailOnly: (email) => {
    if (!email) {
      throw new AppError(
        'Email is required',
        400,
        'EMAIL_REQUIRED'
      );
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      throw new AppError(
        'Invalid email format',
        400,
        'INVALID_EMAIL_FORMAT'
      );
    }
  },

  validateUsernameFormat: (username) => {
    const usernameRegex = /^[a-zA-Z0-9_]{3,30}$/;
    if (!usernameRegex.test(username)) {
      throw new AppError(
        'Invalid username format. Use 3–30 alphanumeric characters.',
        400,
        'INVALID_USERNAME_FORMAT'
      );
    }
  },

  validatePasswordStrength: (password) => {
    const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/;
    if (!passwordRegex.test(password) || !password) {
      throw new AppError(
        'Password must be at least 8 characters, include letters and numbers',
        400,
        'WEAK_PASSWORD_COMPLEXITY'
      );
    }
  }
};

module.exports = validators;
