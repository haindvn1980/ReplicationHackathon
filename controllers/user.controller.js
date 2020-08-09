const validator = require('validator');
const User = require('../models/user.model.js');
var session = require('express-session');
const passport = require('passport');
const crypto = require('crypto');
const { promisify } = require('util');
const nodemailer = require('nodemailer');
const randomBytesAsync = promisify(crypto.randomBytes);

/***************************************************************
 * GET /signup
 * Signup page.
 ***************************************************************/
exports.getSignup = (req, res) => {
  //if the User has already logged in before.
  if (req.user) {
    return res.redirect('/');
  }
  //render to html page
  res.render('account/signup.ejs', { title: 'Create Account' });
}

/****************************************************************
 * POST /signup
 ***************************************************************/
exports.postSignup = (req, res, next) => {
  const validationErrors = [];
  if (!validator.isEmail(req.body.email)) validationErrors.push({ msg: 'Please enter a valid email address.' });
  if (!validator.isLength(req.body.password, { min: 8 })) validationErrors.push({ msg: 'Password must be at least 8 characters long' });
  if (req.body.password !== req.body.confirmPassword) validationErrors.push({ msg: 'Passwords do not match' });
  //kiem tra xem co loi khong
  if (validationErrors.length) {
    req.flash('errors', validationErrors);
    return res.redirect('account/signup');
  }
  req.body.email = validator.normalizeEmail(req.body.email, { gmail_remove_dots: false });

  //setup
  const user = new User({
    email: req.body.email,
    password: req.body.password
  });
  // hàm kiểm tra xem đã có email chưa, kết quả đưa vào (err, existingUser) có lỗi hoặc kq
  User.findOne({ email: req.body.email }, (err, existingUser) => {
    //kiểm soát lỗi
    if (err) { return next(err); }
    //nếu có email rồi thì trả về
    if (existingUser) {
      req.flash('errors', { msg: 'Account with that email address already exists.' });
      return res.redirect('/signup');
    }
    //ghi bản ghi vào db. trước khi lưu vào db sẽ phải gọi hàm pre.save đe ma hoa pw
    user.save((err) => {
      if (err) { return next(err); }
      //gọi hàm Passport login để đăng ký cho user vừa đăng ký thành công.
      req.logIn(user, (err) => {
        if (err) {
          return next(err);
        }
        res.redirect('/');
      });
    });
  });
};

/**
* GET /login
* Login page.
*/
exports.getLogin = (req, res) => {
  if (req.user) {
    return res.redirect('/');
  }
  res.render('account/login.ejs', { title: 'Login' });
}

/**
 * POST /login
 * Sign in using email and password.
 */
exports.postLogin = (req, res, next) => {
  const validationErrors = [];
  if (!validator.isEmail(req.body.email)) validationErrors.push({ msg: 'Please enter a valid email address.' });
  if (validator.isEmpty(req.body.password)) validationErrors.push({ msg: 'Password cannot be blank.' });
  if (validationErrors.length) {
    req.flash('errors', validationErrors);
    return res.redirect('/signup');
  }

  req.body.email = validator.normalizeEmail(req.body.email, { gmail_remove_dots: false });
  //chạy cái middleware passport.authenticate 
  //Nó lấy dữ liệu req.body.username và req.body.passport rồi gán cho hàm verify local.
  passport.authenticate('local', (err, user, info) => {
    if (err) { return next(err); }
    if (!user) {
      req.flash('errors', info);
      return res.redirect('/login');
    }
    req.logIn(user, (err) => {
      if (err) { return next(err); }
      req.flash('success', { msg: 'Success! you are logged in.' });
      res.redirect(req.session.returnTo || '/');
    });
  })(req, res, next);
}

/**
 * GET /logout
 * Log out.
 */
exports.getLogout = (req, res) => {
  //call function logout Passport  - huy phien lam viec cua user
  req.logout();
  //hủy session - destroy session
  req.session.destroy((err) => {
    if (err) console.log('Error : Failed to destroy the session during logout.', err);
    req.user = null;
    res.redirect('/');
  })
}

/**
 * GET /Forgot
 * Log out.
 */
exports.getForgot = (req, res) => {
  //kiem tra authen
  if (req.isAuthenticated()) {
    return res.redirect('/');
  }
  res.render('account/forgot', {
    title: 'Forgot Password'
  });
}

/**
 * POST /forgot
 * Create a random token, then the send user an email with a reset link.
 */
exports.postForgot = (req, res, next) => {
  //check input
  const validationErrors = [];
  if (!validator.isEmail(req.body.email)) validationErrors.push({ msg: 'Please enter a valid email address.' });
  if (validationErrors.length) {
    req.flash('errors', validationErrors);
    return res.redirect('/forgot');
  }
  req.body.email = validator.normalizeEmail(req.body.email, { gmail_remove_dots: false });
  //tao ra string random
  const createRandomToken = randomBytesAsync(16).then((buf) => buf.toString('hex'));
  //
  const setRandomToken = (token) =>
    //tìm xem có email trong db không
    User.findOne({ email: req.body.email }).then((user) => {
      if (!user) {
        req.flash('errors', { msg: 'Account with that email address does not exist.' });
      } else {
        user.passwordResetToken = token;
        user.passwordResetExpires = Date.now() + 3600000; // 1 hour
        user = user.save();
      }
      return user;
    });
  //gui email thong bao click vao link de reset pw
  const sendForgotPasswordEmail = (user) => {
    if (!user) { return; }
    const token = user.passwordResetToken;
    //thiet lap email gui
    let transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.ID_USER,
        pass: process.env.ID_PASSWORD
      }
    });
    //thiet lap noi dung email
    const mailOptions = {
      to: user.email,
      from: 'haindvn@starter.com',
      subject: 'Reset your password on Hackathon Starter',
      text: `You are receiving this email because you (or someone else) have requested the reset of the password for your account.\n\n
            Please click on the following link, or paste this into your browser to complete the process:\n\n
            http://${req.headers.host}/reset/${token}\n\n
            If you did not request this, please ignore this email and your password will remain unchanged.\n`
    };
    //thuc hien gui mail
    return transporter.sendMail(mailOptions)
      .then(() => {
        req.flash('info', { msg: `An e-mail has been sent to ${user.email} with further instructions.` });
      })
      //co loi xay ra thi gui lai 1 lan nua
      .catch((err) => {
        if (err.message === 'self signed certificate in certificate chain') {
          console.log('WARNING: Self signed certificate in certificate chain. Retrying with the self signed certificate. Use a valid certificate if in production.');
          transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
              user: process.env.ID_USER,
              pass: process.env.ID_PASSWORD
            },
            tls: {
              rejectUnauthorized: false
            }
          });
          //gui email thong bao
          return transporter.sendMail(mailOptions)
            .then(() => {
              req.flash('info', { msg: `An e-mail has been sent to ${user.email} with further instructions.` });
            });
        }
        //vẫn lỗi thì sẽ show ra thong bao
        console.log('ERROR: Could not send forgot password email after security downgrade.\n', err);
        req.flash('errors', { msg: 'Error sending the password reset message. Please try again shortly.' });
        return err;
      });
  };

  createRandomToken
    .then(setRandomToken)
    .then(sendForgotPasswordEmail)
    .then(() => res.redirect('/forgot'))
    .catch(next);
}

/**
 * GET /reset/:token
 * Reset Password page.
 */
exports.getReset = (req, res, next) => {

  if (req.isAuthenticated()) {
    return res.redirect('/');
  }
  //check loi input
  const validationErrors = [];
  if (!validator.isHexadecimal(req.params.token)) validationErrors.push({ msg: 'Invalid Token.  Please retry.' });
  if (validationErrors.length) {
    req.flash('errors', validationErrors);
    return res.redirect('/forgot');
  }

  //tim xem co token trong db khong và check xem con han ko???
  User
    .findOne({ passwordResetToken: req.params.token })
    .where('passwordResetExpires').gt(Date.now())
    .exec((err, user) => {
      if (err) { return next(err); }
      if (!user) {
        req.flash('errors', { msg: 'Password reset token is invalid or has expired.' });
        return res.redirect('/forgot');
      }
      res.render('account/reset', {
        title: 'Password Reset'
      });
    });
};

/**
 * POST /reset/:token
 * Process the reset password request.
 */
exports.postReset = (req, res, next) => {
  //check input
  const validationErrors = [];
  if (!validator.isLength(req.body.password, { min: 8 })) validationErrors.push({ msg: 'Password must be at least 8 characters long' });
  if (req.body.password !== req.body.confirm) validationErrors.push({ msg: 'Passwords do not match' });
  if (!validator.isHexadecimal(req.params.token)) validationErrors.push({ msg: 'Invalid Token.  Please retry.' });

  console.log(req.params.token);

  if (validationErrors.length) {
    req.flash('errors', validationErrors);
    return res.redirect('back');
  }

  const resetPassword = () =>
    User
      .findOne({ passwordResetToken: req.params.token })
      .where('passwordResetExpires').gt(Date.now())
      .then((user) => {
        if (!user) {
          req.flash('errors', { msg: 'Password reset token is invalid or has expired.' });
          return res.redirect('back');
        }
        user.password = req.body.password;
        user.passwordResetToken = undefined;
        user.passwordResetExpires = undefined;
        return user.save().then(() => new Promise((resolve, reject) => {
          req.logIn(user, (err) => {
            if (err) { return reject(err); }
            resolve(user);
          });
        }));
      });

  const sendResetPasswordEmail = (user) => {
    if (!user) { return; }
    let transporter = nodemailer.createTransport({
      service: 'SendGrid',
      auth: {
        user: process.env.ID_USER,
        pass: process.env.ID_PASSWORD
      }
    });
    const mailOptions = {
      to: user.email,
      from: 'hackathon@starter.com',
      subject: 'Your Hackathon Starter password has been changed',
      text: `Hello,\n\nThis is a confirmation that the password for your account ${user.email} has just been changed.\n`
    };
    return transporter.sendMail(mailOptions)
      .then(() => {
        req.flash('success', { msg: 'Success! Your password has been changed.' });
      })
      .catch((err) => {
        if (err.message === 'self signed certificate in certificate chain') {
          console.log('WARNING: Self signed certificate in certificate chain. Retrying with the self signed certificate. Use a valid certificate if in production.');
          transporter = nodemailer.createTransport({
            service: 'SendGrid',
            auth: {
              user: process.env.ID_USER,
              pass: process.env.ID_PASSWORD
            },
            tls: {
              rejectUnauthorized: false
            }
          });
          return transporter.sendMail(mailOptions)
            .then(() => {
              req.flash('success', { msg: 'Success! Your password has been changed.' });
            });
        }
        console.log('ERROR: Could not send password reset confirmation email after security downgrade.\n', err);
        req.flash('warning', { msg: 'Your password has been changed, however we were unable to send you a confirmation email. We will be looking into it shortly.' });
        return err;
      });
  };

  resetPassword()
    .then(sendResetPasswordEmail)
    .then(() => { if (!res.finished) res.redirect('/'); })
    .catch((err) => next(err));
};

/**
 * GET /account
 * Profile page.
 */
exports.getAccount = (req, res) => {
  res.render('account/profile.ejs', {
    title: 'Account Management'
  });
};

/**
 * POST /account/profile
 * Update profile information.
 */
exports.postUpdateProfile = (req, res, next) => {
  const validationErrors = [];
  if (!validator.isEmail(req.body.email)) validationErrors.push({ msg: 'Please enter a valid email address.' });

  if (validationErrors.length) {
    req.flash('errors', validationErrors);
    return res.redirect('/account');
  }
  req.body.email = validator.normalizeEmail(req.body.email, { gmail_remove_dots: false });
  //find id
  User.findById(req.user.id, (err, user) => {
    //have err
    if (err) { return next(err) }
    //check email, neu khong phai email cu thi bao xac thuc false
    if (user.email != req.body.email) {
      user.emailVerified = false;
    }
    //lay gia tri
    user.email = req.body.email || '';
    user.profile.name = req.body.name || '';
    user.profile.gender = req.body.gender || '';
    user.profile.location = req.body.location || '';
    user.profile.website = req.body.website || '';

    user.save((err) => {
      //neu qua trinh save gap loi
      if (err) {
        if (err.code === 11000) {
          req.flash('errors', { msg: 'The email address you have entered is already associated with an account.' });
          return res.redirect('/account');
        }
        return next(err);
      }
      //thong bao thanh cong
      req.flash('success', { msg: 'Profile information has been updated.' });
      res.redirect('/account');
    });
  });

}

/**
 * POST /account/password
 * Update current password.
 */
exports.postUpdatePassword = (req, res, next) => {
  //kiem tra xem du lieu nhap vao co du 8 ky tu và khop nhau khong
  const validationErrors = [];
  if (!validator.isLength(req.body.password, { min: 8 })) validationErrors.push({ msg: 'Password must be at least 8 characters long' });
  if (req.body.password !== req.body.confirmPassword) validationErrors.push({ msg: 'Passwords do not match' });
  //neu co thi show loi
  if (validationErrors.length) {
    req.flash('errors', validationErrors);
    return res.redirect('/account');
  }
  //tim kiem user hien tại
  User.findById(req.user.id, (err, user) => {
    if (err) { return next(err); }
    user.password = req.body.password;
    //sẽ gọi hàm trước khi save là userSchema.pre('save', function save(next) ) để mã hóa
    user.save((err) => {
      if (err) { return next(err); }
      req.flash('success', { msg: 'Password has been changed.' });
      res.redirect('/account');
    });
  });
};

/**
 * POST /account/delete
 * Delete user account.
 */
exports.postDeleteAccount = (req, res, next) => {
  User.deleteOne({ _id: req.user.id }, (err) => {
    if (err) { return next(err); }
    req.logout();
    req.flash('info', { msg: 'Your account has been deleted.' });
    res.redirect('/');
  });
};


/**
 * GET /account/verify
 * Verify email address
 */
exports.getVerifyEmail = (req, res, next) => {
  //kiểm tra nếu user đã verified rồi thi thôi
  if (req.user.emailVerified) {
    req.flash('info', { msg: 'The email address has been verified.' });
    return res.redirect('/account');
  }
  //check email đầu vào, có lỗi thì báo
  if (!validator.isEmail(req.user.email)) {
    req.flash('errors', { msg: 'The email address is invalid or disposable and can not be verified.  Please update your email address and try again.' });
    return res.redirect('/account');
  }
  //tạo chuỗi random
  const createRandomToken = randomBytesAsync(16)
    .then((buf) => buf.toString('hex'));
  //tạo token random
  const setRandomToken = (token) => {
    User
      .findOne({ email: req.user.email })
      .then((user) => {
        user.emailVerificationToken = token;
        user = user.save();
      });
    return token;
  };
  //gui email
  const sendVerifyEmail = (token) => {
    let transporter = nodemailer.createTransport({
      service: 'SendGrid',
      auth: {
        user: process.env.ID_USER,
        pass: process.env.ID_PASSWORD
      }
    });
    //thiet lap email
    const mailOptions = {
      to: req.user.email,
      from: 'hackathon@starter.com',
      subject: 'Please verify your email address on Hackathon Starter',
      text: `Thank you for registering with hackathon-starter.\n\n
        This verify your email address please click on the following link, or paste this into your browser:\n\n
        http://${req.headers.host}/account/verify/${token}\n\n
        \n\n
        Thank you!`
    };
    //gui email
    return transporter.sendMail(mailOptions)
      .then(() => {
        req.flash('info', { msg: `An e-mail has been sent to ${req.user.email} with further instructions.` });
      })
      .catch((err) => {
        if (err.message === 'self signed certificate in certificate chain') {
          console.log('WARNING: Self signed certificate in certificate chain. Retrying with the self signed certificate. Use a valid certificate if in production.');
          transporter = nodemailer.createTransport({
            service: 'SendGrid',
            auth: {
              user: process.env.ID_USER,
              pass: process.env.ID_PASSWORD
            },
            tls: {
              rejectUnauthorized: false
            }
          });
          //neu gap loi thi gui lai 1 lan nua
          return transporter.sendMail(mailOptions)
            .then(() => {
              req.flash('info', { msg: `An e-mail has been sent to ${req.user.email} with further instructions.` });
            });
        }
        //bao loi khong gui duoc email
        console.log('ERROR: Could not send verifyEmail email after security downgrade.\n', err);
        req.flash('errors', { msg: 'Error sending the email verification message. Please try again shortly.' });
        return err;
      });
  };

  createRandomToken
    .then(setRandomToken)
    .then(sendVerifyEmail)
    .then(() => res.redirect('/account'))
    .catch(next);
};


/**
 * GET /account/verify/:token
 * Verify email address
 * sau khi click link trong email, thì ham nay được gọi
 */
exports.getVerifyEmailToken = (req, res, next) => {
  //kiểm tra nếu email đã được verified (kích hoạt) rồi thì thôi
  if (req.user.emailVerified) {
    req.flash('info', { msg: 'The email address has been verified.' });
    return res.redirect('/account');
  }
  //check input
  const validationErrors = [];
  if (req.params.token && (!validator.isHexadecimal(req.params.token))) validationErrors.push({ msg: 'Invalid Token.  Please retry.' });
  if (validationErrors.length) {
    req.flash('errors', validationErrors);
    return res.redirect('/account');
  }

  //
  if (req.params.token === req.user.emailVerificationToken) {
    User
      .findOne({ email: req.user.email })
      .then((user) => {
        if (!user) {
          req.flash('errors', { msg: 'There was an error in loading your profile.' });
          return res.redirect('back');
        }
        user.emailVerificationToken = '';
        user.emailVerified = true;
        user = user.save();
        req.flash('info', { msg: 'Thank you for verifying your email address.' });
        return res.redirect('/account');
      })
      .catch((error) => {
        console.log('Error saving the user profile to the database after email verification', error);
        req.flash('errors', { msg: 'There was an error when updating your profile.  Please try again later.' });
        return res.redirect('/account');
      });
  } else {
    req.flash('errors', { msg: 'The verification link was invalid, or is for a different account.' });
    return res.redirect('/account');
  }
};

