const jwt = require('../utils/jwt');
const { isTokenBlacklisted } = require('../utils/tokenBlacklist');

const checkBlacklist = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      status: 'fail',
      message: 'Authorization token missing',
      statusCode: 'NO_TOKEN',
      data: null,
    });
  }

  const token = authHeader.split(' ')[1];

  // Check if token is blacklisted
  if (isTokenBlacklisted(token)) {
    return res.status(401).json({
      status: 'fail',
      message: 'Token has been revoked. Please login again.',
      statusCode: 'TOKEN_REVOKED',
      data: null,
    });
  }
};

module.exports = checkBlacklist;
