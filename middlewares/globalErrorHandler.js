const AppError = require('../utils/appError');

const globalErrorHandler = (err, req, res, next) => {
  // If the error is not an instance of AppError, convert it to one (unexpected errors)
  if (!(err instanceof AppError)) {
    console.error('Unexpected Error:', err);
    err = new AppError('Something went wrong on the server', 500, 'INTERNAL_SERVER_ERROR');
  }

  // Send error response
  res.status(err.httpCode).json({
    status: err.status,
    statusCode: err.statusCode,
    message: err.message,
    // optionally include stack trace only in development
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack }),
    data: null,
  });
};

module.exports = globalErrorHandler;
