const validators = {
  validateNewUser: ({ username, email, password }) => {
    if (!username || !email || !password) {
      return {
        httpCode: 400,
        status: 'fail',
        message: 'Missing required fields',
        statusCode: 'MISSING_FIELDS',
        data: null,
      };
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return {
        httpCode: 400,
        status: 'fail',
        message: 'Invalid email format',
        statusCode: 'INVALID_EMAIL_FORMAT',
        data: null,
      };
    }

    if (password.length < 8) {
      return {
        httpCode: 400,
        status: 'fail',
        message: 'Password too short (minimum 8 characters)',
        statusCode: 'WEAK_PASSWORD',
        data: null,
      };
    }

    return null;
  },

  validateLoginUser: ({ username, password }) => {
    if (!username || !password) {
      return {
        httpCode: 400,
        status: 'fail',
        message: 'Username and password are required',
        statusCode: 'MISSING_CREDENTIALS',
        data: null,
      };
    }

    return null;
  },

  validateEmailOnly: (email) => {
    if (!email) {
      return {
        httpCode: 400,
        status: 'fail',
        message: 'Email is required',
        statusCode: 'EMAIL_REQUIRED',
        data: null,
      };
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return {
        httpCode: 400,
        status: 'fail',
        message: 'Invalid email format',
        statusCode: 'INVALID_EMAIL_FORMAT',
        data: null,
      };
    }

    return null;
  },

  validateUsernameFormat: (username) => {
    const usernameRegex = /^[a-zA-Z0-9_]{3,30}$/;
    if (!usernameRegex.test(username)) {
      return {
        httpCode: 400,
        status: 'fail',
        message: 'Invalid username format. Use 3-30 alphanumeric characters.',
        statusCode: 'INVALID_USERNAME_FORMAT',
        data: null,
      };
    }
    return null;
  },

  validatePasswordStrength: (password) => {
    const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/;
    if (!passwordRegex.test(password)) {
      return {
        httpCode: 400,
        status: 'fail',
        message: 'Password must be at least 8 characters, include letters and numbers',
        statusCode: 'WEAK_PASSWORD_COMPLEXITY',
        data: null,
      };
    }
    return null;
  }
};

module.exports = validators;
