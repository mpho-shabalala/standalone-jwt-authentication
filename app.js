
const authenticationRouter = require('./Routes/authenticationRoutes');
const errorHandler = require('./middlewares/globalErrorHandler')
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const morgan = require('morgan');
require('dotenv').config();

//intantiate express app
const app = express();

//set up middlewares
app.use(cors({origin: '*'}));
app.use(bodyParser.json());
app.use(express.json());
app.use(express.urlencoded({extended: true}));
app.use(morgan('dev'));
// block chrome's favicon router
app.use('/favicon.ico', (req, res) => {
    res.status(404).end();
});

//main authentication middleware
app.use('/api/v1/authentication', authenticationRouter);

app.all('*', (req, res, next) => {
  const err = new Error(`Can't find ${req.originalUrl} on the server`);
  err.statusCode = 404;
  err.customCode = 'ROUTE_NOT_FOUND';
  next(err);
});

app.use(errorHandler);



module.exports = app;