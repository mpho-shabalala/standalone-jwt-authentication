process.on('uncaughtException', error => {
    console.log(error.name, error.message);
    process.exit(1);
});

const app = require('./app');

const server = app.listen(5000, () => {
    console.log('server listening on port 5000')
});

process.on('unhandledRejection', error => {
    console.log(error.name, error.message);
    // close the server when unhandled rejection occurs
    server.close(() => {
      process.exit(1);
    });
})