const jwt = require('jsonwebtoken');

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({
      status: 'fail',
      message: 'Authentication token is missing',
      statusCode: 'TOKEN_MISSING',
      data: null
    });
  }

  try {
    const user = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    req.user = user;
    next();
  } catch (err) {
    let statusCode = 'INVALID_TOKEN';
    let message = 'Invalid authentication token';

    if (err.name === 'TokenExpiredError') {
      statusCode = 'TOKEN_EXPIRED';
      message = 'Authentication token has expired';
    } else if (err.name === 'JsonWebTokenError') {
      statusCode = 'INVALID_TOKEN';
      message = 'Malformed or invalid authentication token';
    } else if (err.name === 'NotBeforeError') {
      statusCode = 'TOKEN_NOT_ACTIVE_YET';
      message = 'Authentication token not active yet';
    }

    return res.status(401).json({
      status: 'fail',
      message,
      statusCode,
      data: null
    });
  }
}

module.exports = authenticateToken;
