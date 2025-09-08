const jwt = require('jsonwebtoken');
const AppError = require('./appError')

const jwtUtils = {
   signToken: (payload, expiresIn = '7d') => {
    try {
      return jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET, { expiresIn });
    } catch (err) {
      throw new AppError('Failed to sign access token', 500, 'TOKEN_SIGN_ERROR');
    }
  },

  signRefreshToken: (payload, expiresIn = '1h') => {
    try {
      return jwt.sign(payload, process.env.REFRESH_TOKEN_SECRET, { expiresIn });
    } catch (err) {
      throw new AppError('Failed to sign refresh token', 500, 'REFRESH_TOKEN_SIGN_ERROR');
    }
  },

  verifyToken: (token) => {
    try {
      return jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    } catch (err) {
      let message = 'Invalid access token';
      let statusCode = 'INVALID_TOKEN';

      if (err.name === 'TokenExpiredError') {
        message = 'Access token expired';
        statusCode = 'TOKEN_EXPIRED';
      }
      throw new AppError(message, 401, statusCode);
    }
  },

  verifyRefreshToken: (token) => {
    try {
      return jwt.verify(token, process.env.REFRESH_TOKEN_SECRET);
    } catch (err) {
      let message = 'Invalid refresh token';
      let statusCode = 'INVALID_REFRESH_TOKEN';

      if (err.name === 'TokenExpiredError') {
        message = 'Refresh token expired';
        statusCode = 'REFRESH_TOKEN_EXPIRED';
      }

      throw new AppError(message, 403, statusCode);
    }
  }
};

module.exports = jwtUtils;
