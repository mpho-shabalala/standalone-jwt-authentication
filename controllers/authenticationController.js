
const authService = require('../services/authenticationService');
const { extractToken } = require('../utils/tokenExtractor.js');
const catchAsync = require('../utils/catchAsync.js')



exports.forgotPassword = catchAsync(async (req, res) => {
  const { email } = req.body;
  const result = await authService.forgotPassword(email);
  return res.status(result.httpCode).json(result);
});

exports.resetPassword = catchAsync(async (req, res) => {
  const { token, newPassword } = req.body;
  const result = await authService.resetPassword(token, newPassword);
  return res.status(result.httpCode).json(result);
});

exports.getUser = catchAsync(async (req, res) => {
  const { username, password } = req.body;
  const result = await authService.loginUser({ username, password });
   if (result.data?.refreshToken) {
    res.cookie('refreshToken', result.data.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });
    delete result.data.refreshToken; // optionally hide it from frontend
  }
  return res.status(result.httpCode).json(result);
});


exports.postUser = catchAsync(async (req, res) => {
  const result = await authService.registerUser(req.body);
  return res.status(result.httpCode).json({result
  });
});

//verify user
exports.verifyUser = catchAsync(async (req, res) => {
  const authHeader = req.headers.authorization;
  const token = await extractToken(authHeader);
  const result = await authService.verifyUser(token);
  return res.status(result.httpCode).json(result);
});

// refresh token
exports.refreshAccessToken = catchAsync(async (req, res) => {
    const refreshToken = req.cookies.refreshToken;

    const result = await authService.refreshToken(refreshToken);
    // Send new access token in response body
    return res.status(result.httpCode).json(result);
});


// logout user
exports.logoutUser = catchAsync(async (req, res) => {
  const authHeader = req.headers.authorization;
  const token = await extractToken(authHeader);
   const result = await authService.logoutUser(token);
  return res.status(result.httpCode).json(result);
});


