# File with heading

1. Install project: npm init
2. Install some dependencies in project nodejs

- express: project framework
- Body-parser: body parser middleware
- express-flash: Flash Messages for your Express Application
    Requires: cookieParser,session
- cookie-parser: cookFast cookie parser.
- multer: Multer is a node.js middleware for handling multipart/form-data
- dotenv: Dotenv is a zero-dependency module that loads environment variables from a .env file into process.env
- passport:Passport is Express-compatible authentication middleware for Node.js.
- validator:A library of string validators and sanitizers.
- express-session:Session data is stored server-side
- Node-sass: is a library that provides binding for Node.js to LibSass, the C version of the popular stylesheet preprocessor, Sass.
- mongoose: Mongoose is a MongoDB object modeling tool designed to work in an asynchronous environment. Mongoose supports both promises and callbacks.
- connect-mongo: MongoDB session store for Connect and Express
- chalk: Highlights text
- bcrypt:A library to help you hash passwords.
- passport-local:  Passport strategy for authenticating with a username and password.
- passport-google-oauth: Google (OAuth) authentication strategies for Passport.
- passport-oauth:OAuth is a standard protocol that allows users to authorize API access to web and desktop or mobile applications
- nodemailer:Nodemailer is a module for Node.js to send emails.
- crypto:The crypto module is a wrapper for OpenSSL cryptographic functions. It supports calculating hashes, authentication with HMAC, ciphers, and more!
- lusca:Web application security middleware.

3.Create app.js page
  3.1 Declare:
    - Module dependencies
    - Load environment variables
    - Controllers
    - API keys and Passport configuration
    - Create Express server.
    - Connect to MongoDB.
    - Express configuration
    - Primary app routes
    - API examples routes
    - Auth authentication routes. (Sign in)
    - Auth authorization routes. (API examples)
    - Error Handler.
    - Start Express server.

4.Function
  4.1 Account:
    - Register account
    - Register account with google AIP
    - Register account with facebook AIP
    - Login
    - Logout
