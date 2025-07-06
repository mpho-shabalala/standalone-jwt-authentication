const rateLimit = require('express-rate-limit');

const roleLimits = {
  admin: { windowMs: 60 * 1000, max: 30 },
  user: { windowMs: 60 * 1000, max: 10 },
  guest: { windowMs: 60 * 1000, max: 5 }, // for unauthenticated
};

// General fallback config
const defaultLimit = { windowMs: 60 * 1000, max: 5 };

const createRateLimiter = () =>
  rateLimit({
    windowMs: defaultLimit.windowMs,
    max: defaultLimit.max, // default unless overridden below
    keyGenerator: (req) => {
      const ip = req.ip;
      const userID = req.user?.userID || 'guest';
      return `${ip}_${userID}`;
    },
    handler: (req, res) => {
      return res.status(429).json({
        httpCode: 429,
        status: 'fail',
        message: 'Too many requests. Please slow down.',
        statusCode: 'TOO_MANY_REQUESTS',
        data: null,
      });
    },
    // Dynamically adjust max requests based on role
    max: (req, res) => {
      const role = req.user?.role || 'guest';
      return roleLimits[role]?.max || defaultLimit.max;
    },
    standardHeaders: true,
    legacyHeaders: false,
  });

  const rateLimiter = createRateLimiter();

module.exports = {rateLimiter};
