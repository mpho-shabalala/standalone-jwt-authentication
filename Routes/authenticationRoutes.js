const express = require('express');
const authenticationController = require('../controllers/authenticationController');
const router = express.Router();
const {rateLimiter} = require('../middlewares/rateLimiter')
const passport = require('passport');

// not authenticated
//rate limiter middleware is executed at router level because it is role dependent(users role on the app)
router.route('/login').post(
  // rateLimiter,
   authenticationController.getUser);
router.route('/recover_account').post(rateLimiter,authenticationController.forgotPassword)
router.route('/verify_user').post(rateLimiter,authenticationController.verifyUser);
router.route('/register').post(rateLimiter,authenticationController.postUser)
// .get(authenticationController.getAllAuthenticatedUsers);

//authenticated
router.route('/reset_password').post(rateLimiter,authenticationController.resetPassword)
router.route('/validate_user').post(
  // rateLimiter,
  authenticationController.validateToken)
router.route('/refresh_token').get(
  // rateLimiter,
  authenticationController.refreshAccessToken);
router.route('/logout').post(authenticationController.logoutUser);

//----------OAuth authentication-------------

// Step 1: Redirect to Google
router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

// Step 2: Callback after Google login
router.get(
  '/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  authenticationController.googleCallback
);



module.exports = router;