// services/authService.js

const shortid = require('shortid');
const bcrypt = require('bcrypt');
const jwt = require('../utils/jwt');
const { sendVerificationEmail, sendPasswordResetEmail } = require('../utils/mailer');
const { readData, writeData } = require('../utils/fileHandler');
const { validateNewUser, validateLoginUser , validatePasswordStrength, validateEmailOnly} = require('../utils/validators');
const userDBPath = '../Backend/database/users.json';
const { signToken, verifyToken } = require('../utils/jwt');
const {addTokenToBlacklist} = require('../utils/tokenBlacklist');
const AppError = require('../utils/appError');
// const AppError = require('../utils/appError');

const authService = {};



authService.registerUser = async (userInput) => {
  const { username, email, password, contacts, acceptNewsletter } = userInput;
  
  // Step 1: Validate inputs
  validateNewUser({username, email, password});
  console.log(password)
  // Step 2: Read users
  const data = readData(userDBPath);
  // Step 3: Check for duplicate user
  const userExists = data.users.some(
    u => u.username === username || u.email === email
  );

  if (userExists) {
    throw new AppError('A user with that username or email already exists.', 409, 'USER_EXISTS' );
  }

  // Step 4: Hash password
  const hashedPassword = await bcrypt.hash(password, 10);
  // Step 5: Create new user object
  const newUser = {
    userID: shortid.generate(),
    username,
    email,
    contacts,
    password: hashedPassword,
    acceptNewsletter: acceptNewsletter === 'on',
    emailVerified: false,
    role: 'user',
    createdAt: new Date().toISOString()
  };

 
  // Step 6: Save to DB
  data.users.push(newUser);
  writeData(userDBPath, data);

 
  // Step 7: Send verification email
  
  try {
    const token = jwt.signToken({ userID: newUser.userID, role: newUser.role }, '15m');

    await sendVerificationEmail(email, token, username);
    
  } catch (err) {
    throw new AppError('Failed to send verification email', 500, 'EMAIL_SEND_FAILED' );
  }

  // Step 8: Return success
  return {
    httpCode: 201,
    status: 'success',
    message: 'Registration successful. Verification email sent.',
    statusCode: 'AWAITING_VERIFICATION',
  };
};

//AOUTH REGISTER
authService.registerOAuthUser = async (profile, provider) => {
  // Step 1: Read current users
  const data = readData(userDBPath);

  // Step 2: Check if OAuth user already exists
  let user = data.users.find(
    u => u.provider === provider && u.providerId === profile.id
  );

  if (user) {
    // Existing OAuth user → issue JWT
    const token = jwt.signToken({ userID: user.userID, role: user.role }, '1h');
    return {
      httpCode: 200,
      status: 'success',
      message: 'OAuth login successful.',
      data: { user, token }
    };
  }

  // Step 3: Check if email exists from traditional registration
  user = data.users.find(u => u.email === profile.email);

  if (user) {
    // Option A: link accounts
    user.provider = provider;
    user.providerId = profile.id;
    writeData(userDBPath, data);

    const token = jwt.signToken({ userID: user.userID, role: user.role }, '1h');
    return {
      httpCode: 200,
      status: 'success',
      message: 'OAuth linked to existing account.',
      data: { user, token }
    };
  }

  // Step 4: New OAuth user → create user
  const newUser = {
    userID: shortid.generate(),
    provider,
    providerId: profile.id,
    username: profile.displayName || profile.email.split('@')[0],
    email: profile.email,
    avatar: profile.photos?.[0]?.value || null,
    role: 'user',
    emailVerified: true,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };

  // Step 5: Save new user
  data.users.push(newUser);
  writeData(userDBPath, data);

  // Step 6: Generate JWT
  const token = jwt.signToken({ userID: newUser.userID, role: newUser.role }, '1h');

  // Step 7: Return response
  return {
    httpCode: 201,
    status: 'success',
    message: 'OAuth registration successful.',
    data: { user: newUser, token }
  };
};


authService.verifyUser = async (token) => {

  try {
    const decoded = verifyToken(token);
    const data = readData(userDBPath);
    const user = data.users.find(u => u.userID === decoded.userID);

    if (!user) {
       throw new AppError('User not found', 404, 'USER_NOT_FOUND' );
    }

    if (user.emailVerified) {
      return {
        httpCode: 200,
        status: 'success',
        message: 'Email already verified',
        statusCode: 'ALREADY_VERIFIED',
        data: null,
      };
    }

    //verify and save to database
    user.emailVerified = true;
    writeData(userDBPath, data);
   
    // create refresh token and access token
    const refreshToken = jwt.signRefreshToken({ userID: user.userID , role:user.role},'7d');
    const accessToken = signToken({ userID: user.userID , role:user.role}, '1h');
    return {
      httpCode: 200,
      status: 'success',
      message: 'Email verified successfully',
      statusCode: 'EMAIL_VERIFIED',
      data: {
        token: accessToken,
        username: user.username,
        refreshToken
      },
    };
  } catch (error) {
    let statusCode = 'EMAIL_VERIFICATION_FAILED';
    let message = 'Email verification failed.';

  if (error.name === 'TokenExpiredError') {
    statusCode = 'TOKEN_EXPIRED';
    message = 'Verification token has expired.';
  } else if (error.name === 'JsonWebTokenError') {
    statusCode = 'INVALID_TOKEN';
    message = 'Verification token is invalid.';
  } else if (error.name === 'NotBeforeError') {
    statusCode = 'TOKEN_NOT_ACTIVE_YET';
    message = 'Token not active yet.';
  }

  return {
    httpCode: 400,
    status: 'fail',
    message,
    statusCode,
    data: null
  };
  }
};


authService.loginUser = async ({ username, password }) => {
  validateLoginUser({username, password})
    const data = readData(userDBPath);
    const user = data.users.find(u => u.username === username);

    if (!user) {
      throw new AppError('Invalid username or password', 401, 'USER_NOT_FOUND' );
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      throw new AppError('Invalid username or password', 401, 'USER_NOT_FOUND' );
    }


    //save refresh token to the cookie
    const refreshToken = jwt.signRefreshToken({ userID: user.userID , role:user.role},'7d');

      
    const token = jwt.signToken({ userID: user.userID , role:user.role},'1h' );
    return {
      httpCode: 200,
      status: 'success',
      message: 'Login successful',
      statusCode: 'USER_FOUND',
      data: {
        token,
        username: user.username,
        refreshToken
      },
    }

  }

authService.validateToken = async (token) => {
  try{
    // step 1: decode the token and check its validity
    const decoded = verifyToken(token);
    // if(!decoded) throw AppError('Token is no longer valid', 404, 'INVALID_TOKEN') 
    // step 2: check user existance
    const data = readData(userDBPath);
    const user = data.users.find(u => u.userID === decoded.userID);
    if(!user) throw AppError('Token is no longer valid', 404, 'INVALID_TOKEN') 
    
    // STEP 3: TOKEN IS VALID return success
    return {
      httpCode: 200,
      status: 'success',
      message: 'User verified successfully',
      statusCode: 'USER_VERIFIED',
      data: null
    };

  }catch(error){
      return {
      httpCode: error.httpCode,
      status: 'fail',
      message: error.message,
      statusCode: error.statusCode,
      data: null
  };
  }
}


authService.resetPassword = async (token, newPassword) => {
  if (!token) {
    throw new AppError('Reset token is required', 400, 'TOKEN_REQUIRED' );
  }

  validatePasswordStrength(newPassword);

  try {
    // Verify token and extract userID
    const decoded = verifyToken(token);
    const userID = decoded.userID;

    // Load user data
    const data = readData(userDBPath);
    const user = data.users.find(u => u.userID === userID);

    if (!user) {
      throw new AppError('User not found', 404, 'USER_NOT_FOUND' );
    }

    // Hash new password
    const saltRounds = parseInt(process.env.SALT_ROUNDS || '10');
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

    // Update password and save
    user.password = hashedPassword;
    writeData(userDBPath, data);

    return {
      httpCode: 200,
      status: 'success',
      message: 'Password reset successfully',
      statusCode: 'PASSWORD_RESET',
      data: null,
    };
  } catch (error) {
    let statusCode = 'RESET_FAILED';
    let message = 'Password reset failed.';

    if (error.name === 'TokenExpiredError') {
      statusCode = 'TOKEN_EXPIRED';
      message = 'Reset token has expired.';
    } else if (error.name === 'JsonWebTokenError') {
      statusCode = 'INVALID_TOKEN';
      message = 'Reset token is invalid.';
    }

    throw new AppError(message, 400, statusCode );
  }
};

authService.forgotPassword = async (email) => {
 validateEmailOnly(email)

  // Read user data
  const data = readData(userDBPath);
  const user = data.users.find(u => u.email === email);

  // Always respond success to avoid leaking user existence
  if (!user) {
    return {
      httpCode: 200,
      status: 'success',
      message: 'If that email exists, a reset link has been sent.',
      statusCode: 'RESET_LINK_SENT',
      data: null,
    };
  }

  try {
    // Send email with reset token link
    const resetToken = jwt.signToken({ userID: user.userID, role: user.role }, '15m')
    await sendPasswordResetEmail(email, resetToken, user.username);

    return {
      httpCode: 200,
      status: 'success',
      message: 'If that email exists, a reset link has been sent.',
      statusCode: 'RESET_LINK_SENT',
      data: null,
    };
  } catch (error) {
    
    return {
      httpCode: 500,
      status: 'fail',
      message: 'Failed to send reset email. Please try again later.',
      statusCode: 'EMAIL_SEND_ERROR',
      data: null,
    };
  }

}

authService.refreshToken = async (refreshToken) => {

  if (!refreshToken) {
    throw new AppError('Refresh token not provided', 401, 'MISSING_REFRESH_TOKEN' );
  }

  try {
    // Verify the refresh token
    const decoded = jwt.verifyRefreshToken(refreshToken);
    const newAccessToken = jwt.signToken({ userID: decoded.userID, role: decoded.role },'1h');

    return {
      httpCode: 200,
      status: 'success',
      statusCode: 'TOKEN_REFRESHED',
      message: 'Access token refreshed successfully',
      data: {
        token: newAccessToken
      }
    };

  } catch (err) {
     throw new AppError('Refresh token is invalid or expired', 403, 'INVALID_REFRESH_TOKEN' );
  }
};

authService.logoutUser =async  () => {
  try{
    const decoded = verifyToken(token);
    const expTimeStamp = decoded.exp * 1000;  //convert to miliseconds
    //blacklist the token
    addTokenToBlacklist(token, expTimeStamp);
      return {
      httpCode: 200,
      status: 'success',
      message: 'User successfully logged out',
      statusCode: 'LOGOUT_SUCCESS',
      data: null,
    };
  }catch(err){
    let statusCode = 'LOGOUT_FAILED';
    let message = 'Could not log out user';

    if (err.name === 'TokenExpiredError') {
      statusCode = 'TOKEN_EXPIRED';
      message = 'Token already expired';
    } else if (err.name === 'JsonWebTokenError') {
      statusCode = 'INVALID_TOKEN';
      message = 'Invalid token';
    }
    throw new AppError(message, 401, statusCode );
  }
    
}

module.exports = authService;
