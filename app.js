/**
 * Module dependencies.
 */
const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const flash = require('express-flash');
const passport = require('passport');
const multer = require('multer');
const path = require('path');
const dotenv = require('dotenv');
const chalk = require("chalk");
const sass = require('node-sass-middleware');
const MongoStore = require('connect-mongo')(session);
const upload = multer({ dest: path.join(__dirname, 'uploads') });
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const expressStatusMonitor = require('express-status-monitor');
const lusca = require('lusca');
var csrf = require('csurf');
var csrfProtection = csrf({ cookie: true })
/**
 * Load environment variables from .env file, where API keys and passwords are configured.
 */
dotenv.config({ path: 'process.env' });

/**
 * Create Express server.
 */
const app = express();

/**
 * Connect to MongoDB.
 */
mongoose.set('useFindAndModify', false);
mongoose.set('useCreateIndex', true);
mongoose.set('useNewUrlParser', true);
mongoose.set('useUnifiedTopology', true);
mongoose.connect(process.env.MONGODB_URI);
mongoose.connection.on('error', (err) => {
  console.error(err);
  console.log('%s MongoDB connection error. Please make sure MongoDB is running.', chalk.red('✗'));
  process.exit();
});

/**
 * Controllers (route handlers).
 */
const homeController = require('./controllers/home.js');
const userController = require('./controllers/user.controller.js');
const contactController = require('./controllers/contact.controller.js');
const apiController = require('./controllers/api.controller.js');

/**
 * API keys and Passport configuration.
 */
const passportConfig = require('./config/passport');


/**
 * Express configuration.
 */
app.set('host', process.env.OPENSHIFT_NODEJS_IP || '0.0.0.0');
app.set('port', process.env.PORT || process.env.OPENSHIFT_NODEJS_PORT || 8888);

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.use(expressStatusMonitor());
app.use(sass({
  src: path.join(__dirname, 'public'),
  dest: path.join(__dirname, 'public')
}));

app.use(session({
  resave: true,
  saveUninitialized: true,
  secret: process.env.SESSION_SECRET,
  cookie: { maxAge: 1209600000 }, // two weeks in milliseconds
  store: new MongoStore({
    url: process.env.MONGODB_URI,
    autoReconnect: true,
  })
}));

app.use(passport.initialize());
app.use(passport.session());
app.use(flash());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
//app.use('/', express.static(path.join(__dirname, 'public'), { maxAge: 31557600000 }));
// app.use('/js/lib', express.static(path.join(__dirname, 'node_modules/chart.js/dist'), { maxAge: 31557600000 }));
// app.use('/js/lib', express.static(path.join(__dirname, 'node_modules/popper.js/dist/umd'), { maxAge: 31557600000 }));
// app.use('/js/lib', express.static(path.join(__dirname, 'node_modules/bootstrap/dist/js'), { maxAge: 31557600000 }));
// app.use('/js/lib', express.static(path.join(__dirname, 'node_modules/jquery/dist'), { maxAge: 31557600000 }));
// app.use('/webfonts', express.static(path.join(__dirname, 'node_modules/@fortawesome/fontawesome-free/webfonts'), { maxAge: 31557600000 }));
app.use((req, res, next) => {
  res.locals.user = req.user;
  next();
});
app.use((req, res, next) => {
  // After successful login, redirect back to the intended page
  if (!req.user
    && req.path !== '/login'
    && req.path !== '/signup'
    && !req.path.match(/^\/auth/)
    && !req.path.match(/\./)) {
    req.session.returnTo = req.originalUrl;
  } else if (req.user
    && (req.path === '/account' || req.path.match(/^\/api/))) {
    req.session.returnTo = req.originalUrl;
  }
  next();
});
app.use((req, res, next) => {
  if (req.path === '/api/upload') {
    // Multer multipart/form-data handling needs to occur before the Lusca CSRF check.
    next();
  } else {
    lusca.csrf()(req, res, next);
  }
});
app.use(lusca.xframe('SAMEORIGIN'));
app.use(lusca.xssProtection(true));
app.use(lusca.p3p('ABCDEF'));
app.use(lusca.hsts({ maxAge: 31536000 }));


/**
 * Primary app routes.
 */
//home page
app.get('/', homeController.index);
//************************/
//register account
app.get('/signup', userController.getSignup);
app.post('/signup', userController.postSignup);
//login
app.get('/login', userController.getLogin);
app.post('/login', userController.postLogin);
//logout
app.get('/logout', userController.getLogout);
//forgot password
app.get('/forgot', userController.getForgot);
app.post('/forgot', csrfProtection, userController.postForgot);
//reset
app.get('/reset/:token', userController.getReset);
app.post('/reset/:token', csrfProtection, userController.postReset);

//************************/
//account show all
app.get('/account', passportConfig.isAuthenticated, userController.getAccount);
//save profile
app.post('/account/profile', passportConfig.isAuthenticated, userController.postUpdateProfile);
//change pw
app.post('/account/password', passportConfig.isAuthenticated, userController.postUpdatePassword);
//delete acc
app.post('/account/delete', passportConfig.isAuthenticated, userController.postDeleteAccount);
//verify email
app.get('/account/verify', passportConfig.isAuthenticated, userController.getVerifyEmail);
app.get('/account/verify/:token', passportConfig.isAuthenticated, userController.getVerifyEmailToken);

//************************/
//contact
app.get('/contact', contactController.getContact);
app.post('/contact', contactController.postContact);

//*********API************************
//**************************
//home
app.get('/api', apiController.getApi);
//upload file
app.get('/api/upload', lusca({ _csrf: true }), apiController.getFileUpload);
app.post('/api/upload', upload.single('myFile'), lusca({ _csrf: true }), apiController.postFileUpload);
//maps
app.get('/api/maps', apiController.getHereMaps);
///app.get('/api/google-maps', apiController.getGoogleMaps);


/**
 * API examples routes.
 */
app.get('/api', apiController.getApi);


/**
 * OAuth authentication routes. (Sign in)
 */
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email', 'https://accounts.google.com/o/oauth2/authe', 'https:/https://oauth2.googleapis.com/token'], accessType: 'offline', prompt: 'consent' }));
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/login' }), (req, res) => {
  res.redirect(req.session.returnTo || '/');
});
app.get('/auth/facebook', passport.authenticate('facebook', { scope: ['email', 'public_profile'] }));
app.get('/auth/facebook/callback', passport.authenticate('facebook', { failureRedirect: '/login' }), (req, res) => {
  res.redirect(req.session.returnTo || '/');
});


/**
 * Start Express server.
 */
app.listen(app.get('port'), () => {
  console.log('%s App is running at http://localhost:%d in %s mode', chalk.green('✓'), app.get('port'), app.get('env'));
  console.log('  Press CTRL-C to stop\n');
});

module.exports = app;
