
const authService = require('../services/authenticationService');
const { extractToken } = require('../utils/tokenExtractor.js');
const catchAsync = require('../utils/catchAsync.js')



// attempt to register new user using credentials and email included
exports.postUser = catchAsync(async (req, res) => {
  const result = await authService.registerUser(req.body);
  return res.status(result.httpCode).json(result);
});

//verify user after signup attempt
exports.verifyUser = catchAsync(async (req, res) => {
  const token = await extractToken(req);
  const result = await authService.verifyUser(token);
  if(result.data.refreshToken){
     res.cookie('refreshToken',result.data.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });
  }
  return res.status(result.httpCode).json(result);
});

//validate token
exports.validateToken = catchAsync(async (req, res) => {
  const token = await extractToken(req);
  const result = await authService.validateToken(token);
  return res.status(result.httpCode).json(result);
})

// attempt to register new user using OAuth 
exports.googleCallback = catchAsync(async (req, res) => {
  const profile = req.user;
  const provider = 'google';

  const result = await authService.registerOAuthUser(profile, provider);
  return res.status(result.httpCode).json(result);
});

exports.getUser = catchAsync(async (req, res) => {
  const { username, password } = req.body;
  console.log({ username, password })
  const result = await authService.loginUser({ username, password });
  if(result.data.refreshToken){
     res.cookie('refreshToken',result.data.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });
  }
  return res.status(result.httpCode).json(result);
});

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

// refresh token
exports.refreshAccessToken = catchAsync(async (req, res) => {
  const refreshToken = req.cookies?.refreshToken;

  if (!refreshToken) {
    return res.status(401).json({
      status: "fail",
      message: "No refresh token provided",
    });
  }

  const result = await authService.refreshToken(refreshToken);
  return res.status(result.httpCode).json(result);
});


// logout user
exports.logoutUser = catchAsync(async (req, res) => {
  const token = await extractToken(req);
   const result = await authService.logoutUser(token);
  return res.status(result.httpCode).json(result);
});


