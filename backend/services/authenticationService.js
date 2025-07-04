// services/authService.js

const shortid = require('shortid');
const bcrypt = require('bcrypt');
const jwt = require('../utils/jwt');
const { sendVerificationEmail, sendPasswordResetEmail } = require('../utils/mailer');
const { readData, writeData } = require('../utils/fileHandler');
const { validateNewUser } = require('../utils/validators');
const userDBPath = '../Backend/database/users.json';
const { signToken, verifyToken } = require('../utils/jwt');
const {addTokenToBlacklist} = require('../utils/tokenBlacklist')

const authService = {};



authService.registerUser = async (userInput) => {
  const { username, email, password, contacts, acceptNewsletter } = userInput;
  console.log('inputs: ',userInput)
  
   console.log('we good upto so far')
  // Step 1: Validate inputs
  const validationError = validateNewUser(userInput);
  if (validationError) return validationError;

  // Step 2: Read users
  const data = readData(userDBPath);
  // Step 3: Check for duplicate user
  const userExists = data.users.some(
    u => u.username === username || u.email === email
  );
  if (userExists) {
    return {
      httpCode: 409,
      status: 'fail',
      message: 'A user with that username or email already exists.',
      statusCode: 'USER_EXISTS',
      data: null
    };
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
    role: 'user'
  };

 
  // Step 6: Save to DB
  data.users.push(newUser);
  writeData(userDBPath, data);

 
  // Step 7: Send verification email
  
  try {
    const token = jwt.signToken({ userID: newUser.userID, role: newUser.role }, '15m');
    await sendVerificationEmail(email, token, username);
    // throw new Error('error')
  } catch (err) {
    return {
      httpCode: 500,
      status: 'fail',
      message: 'Failed to send verification email',
      statusCode: 'EMAIL_SEND_FAILED',
      data: null
    };
  }

  // Step 8: Return success
  return {
    httpCode: 201,
    status: 'success',
    message: 'Registration successful. Verification email sent.',
    statusCode: 'AWAITING_VERIFICATION',
    data: {
      user: {
        username,
        email,
        userID: newUser.userID
      }
    }
  };
};

authService.verifyUser = async (token) => {

  try {
    const decoded = verifyToken(token);
    const data = readData(userDBPath);
    const user = data.users.find(u => u.userID === decoded.userID);

    if (!user) {
      return {
        httpCode: 404,
        status: 'fail',
        message: 'User not found',
        statusCode: 'USER_NOT_FOUND',
        data: null,
      };
    }

    if (user.emailVerified) {
      return {
        httpCode: 200,
        status: 'success',
        message: 'Email already verified',
        statusCode: 'ALREADY_VERIFIED',
        data: { user: null },
      };
    }

    user.emailVerified = true;
    writeData(userDBPath, data);

    const authToken = signToken({ userID: user.userID , role:user.role}, '1h');
    return {
      httpCode: 200,
      status: 'success',
      message: 'Email verified successfully',
      statusCode: 'EMAIL_VERIFIED',
      data: {
        token: authToken,
        user: {
          userID: user.userID,
          username: user.username,
          email: user.email,
        },
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
  if (!username || !password) {
    return {
      httpCode: 400,
      status: 'fail',
      message: 'Username and password are required',
      statusCode: 'MISSING_DETAILS',
      data: null,
    };
  }

  try {
    const data = readData(userDBPath);
    const user = data.users.find(u => u.username === username);

    if (!user) {
      return {
        httpCode: 401,
        status: 'fail',
        message: 'Invalid username or password',
        statusCode: 'USER_NOT_FOUND',
        data: null,
      };
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return {
        httpCode: 401,
        status: 'fail',
        message: 'Invalid username or password',
        statusCode: 'INVALID_PASSWORD',
        data: null,
      };
    }

    const refreshToken = jwt.signRefreshToken({ userID: user.userID , role:user.role},'7d');

    //create and send refresh tokeen to the cookie
    const token = jwt.signToken({ userID: user.userID , role:user.role},'1h' );
    return {
      httpCode: 200,
      status: 'success',
      message: 'Login successful',
      statusCode: 'USER_FOUND',
      data: {
        token,
        refreshToken,
        user: {
          username: user.username,
          email: user.email,
          userID: user.userID,
        },
      },
    };
  } catch (error) {
    // Generic server error handler; JWT errors don't apply here
    return {
      httpCode: 500,
      status: 'fail',
      message: error.message,
      statusCode: 'SERVER_ERROR',
      data: null,
    };
  }
};

authService.resetPassword = async (token, newPassword) => {
  if (!token) {
    return {
      httpCode: 400,
      status: 'fail',
      message: 'Reset token is required',
      statusCode: 'TOKEN_REQUIRED',
      data: null,
    };
  }

  if (!newPassword || newPassword.length < 8) {
    return {
      httpCode: 400,
      status: 'fail',
      message: 'Password must be at least 8 characters long',
      statusCode: 'WEAK_PASSWORD',
      data: null,
    };
  }

  try {
    // Verify token and extract userID
    const decoded = verifyToken(token);
    const userID = decoded.userID;

    // Load user data
    const data = readData(userDBPath);
    const user = data.users.find(u => u.userID === userID);

    if (!user) {
      return {
        httpCode: 404,
        status: 'fail',
        message: 'User not found',
        statusCode: 'USER_NOT_FOUND',
        data: null,
      };
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

    return {
      httpCode: 400,
      status: 'fail',
      message,
      statusCode,
      data: null,
    };
  }
};

authService.forgotPassword = async (email) => {
  if (!email) {
    return {
      httpCode: 400,
      status: 'fail',
      message: 'Email is required',
      statusCode: 'EMAIL_REQUIRED',
      data: null,
    };
  }

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
    return {
      httpCode: 401,
      status: 'fail',
      statusCode: 'MISSING_REFRESH_TOKEN',
      message: 'Refresh token not provided',
      data: null
    };
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
    return {
      httpCode: 403,
      status: 'fail',
      statusCode: 'INVALID_REFRESH_TOKEN',
      message: 'Refresh token is invalid or expired',
      data: null
    };
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

    return {
      httpCode: 401,
      status: 'fail',
      message,
      statusCode,
      data: null,
    };
  }
    
}

module.exports = authService;
