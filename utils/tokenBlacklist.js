// utils/tokenBlacklist.js

const blacklistedTokens = new Set();

const addTokenToBlacklist = (token, exp) => {
  blacklistedTokens.add(token);

  // Automatically remove token after expiration time to free memory
  const now = Math.floor(Date.now() / 1000);
  const delay = (exp - now) * 1000;

  setTimeout(() => {
    blacklistedTokens.delete(token);
  }, delay > 0 ? delay : 0);
};

const isTokenBlacklisted = (token) => {
  return blacklistedTokens.has(token);
};

module.exports = {
  addTokenToBlacklist,
  isTokenBlacklisted,
};
