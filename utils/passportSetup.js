const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const authService = require('../services/authenticationService');
require('dotenv').config()
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const result = await authService.registerOAuthUser(profile, 'google');
        done(null, result.user); // attaches user to req.user
      } catch (err) {
        done(`error: ${err}`, null);
      }
    }
  )
);

passport.serializeUser((user, done) => done(null, user.userID));
passport.deserializeUser((id, done) => {
  // Optional: fetch user by ID from DB if needed
  done(null, { userID: id });
});
