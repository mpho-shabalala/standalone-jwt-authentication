const AppError = require('./appError');

const extractToken = async (authHeader) => {
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    throw new AppError('Authorization header missing or malformed', 401, 'MALFORMED_TOKEN');
  }

  const token = authHeader.split(' ')[1];
  return token ;
};

module.exports = {extractToken};
