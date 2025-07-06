const jwt = require('jsonwebtoken');

const jwtUtils = {
  signToken:  (payload, expiresIn = '7d') => {
    return jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET, { expiresIn });
  },

  signRefreshToken: (payload, expiresIn = '1h') => {
    return jwt.sign(payload, process.env.REFRESH_TOKEN_SECRET, { expiresIn });
  },

  verifyToken:  (token) => {
    return jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
  },

  verifyRefreshToken: (token) => {
     return jwt.verify(token, process.env.REFRESH_TOKEN_SECRET);
  }
};

module.exports = jwtUtils;
