
const authenticationRouter = require('./Routes/authenticationRoutes');
const errorHandler = require('./middlewares/globalErrorHandler');
// const oauthRoutes = require('./Routes/oauthRoutes');
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser')
const morgan = require('morgan');
const session = require('express-session');
const passport = require('passport')
require('./utils/passportSetup');
require('dotenv').config();

//intantiate express app
const app = express();


//set up middlewares

// Session is required for OAuth
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true
}));
app.use(cors({
  origin: "http://localhost:5173", // frontend URL
  credentials: true,               // allow cookies/auth headers
}));
app.use(bodyParser.json());
app.use(express.json());
app.use(express.urlencoded({extended: true}));
app.use(morgan('dev'));
// block chrome's favicon router
app.use('/favicon.ico', (req, res) => {
    res.status(404).end();
});
app.use(passport.initialize());
app.use(passport.session());

//main authentication middleware
app.use('/api/v1/authentication', authenticationRouter);

app.use(cookieParser())
app.all('*', (req, res, next) => {
  const err = new Error(`Can't find ${req.originalUrl} on the server`);
  err.statusCode = 404;
  err.customCode = 'ROUTE_NOT_FOUND';
  next(err);
});

app.use(errorHandler);



module.exports = app;