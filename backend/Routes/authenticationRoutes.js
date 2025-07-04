const express = require('express');
const authenticationController = require('../controllers/authenticationController');
const router = express.Router();
const {rateLimiter} = require('../middlewares/rateLimiter')

// not authenticated
//rate limiter middleware is executed at router level because it is role dependent(users role on the app)
router.route('/login').post(rateLimiter, authenticationController.getUser);
router.route('/recover_account').post(rateLimiter,authenticationController.forgotPassword)
router.route('/verify_user').post(rateLimiter,authenticationController.verifyUser);
router.route('/register').post(rateLimiter,authenticationController.postUser)
// .get(authenticationController.getAllAuthenticatedUsers);

//authenticated
router.route('/renew_password').post(rateLimiter,authenticationController.resetPassword)
router.route('/refresh-token').get(rateLimiter,authenticationController.refreshAccessToken);

router.route('/logout').post(rateLimiter,authenticationController.logoutUser);

module.exports = router;