

const errorHandler = (err, req, res, next) => {
  console.error('Global Error Handler:', err);

  const statusCode = err.statusCode || 500;
  const message = err.message || 'Something went wrong.';
  const status = `${statusCode}`.startsWith('4') ? 'fail' : 'error';

  res.status(statusCode).json({
    httpCode: statusCode,
    status,
    message,
    statusCode: err.customCode || 'UNHANDLED_ERROR',
    data: null
  });
};

module.exports = errorHandler;
