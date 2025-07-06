class AppError extends Error {
  constructor(message, httpCode, statusCode = 'ERROR') {
    super(message);

    this.httpCode = httpCode; // e.g., 400, 401, 404, 500
    this.status = `${httpCode}`.startsWith('4') ? 'fail' : 'error';
    this.statusCode = statusCode; // custom error code string for frontend/client
    this.isOperational = true; // mark as operational error (vs programming or unknown)

    // Capture stack trace, excluding constructor call from it
    Error.captureStackTrace(this, this.constructor);
  }
}

module.exports = AppError;