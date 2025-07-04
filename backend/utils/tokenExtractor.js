const extractToken = async (authHeader) => {
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return {
      error: {
        httpCode: 401,
        status: 'fail',
        message: 'Authorization header missing or malformed',
        statusCode: 'MALFORMED_TOKEN',
        data: null,
      },
      token: null,
    };
  }

  const token = authHeader.split(' ')[1];
  return token ;
};

module.exports = {extractToken};
