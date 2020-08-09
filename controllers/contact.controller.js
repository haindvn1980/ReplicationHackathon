const validator = require('validator');
const nodemailer = require('nodemailer');



exports.getContact = (req, res) => {
  const unknownUser = !(req.user);
  res.render('contact/contact.ejs', {
    title: 'Contact',
    unknownUser,
  })
}

exports.postContact = (req, res, next) => {
  const validationErrors = [];
  let fromName;
  let fromEmail;
  //kiem tra data nhap tu UI. Neu user chua dang nhap thi lay tu UI
  if (!req.user) {
    if (validator.isEmpty(req.body.name)) validationErrors.push({ msg: 'Please enter your name' });
    if (!validator.isEmail(req.body.email)) validationErrors.push({ msg: 'Please enter a valid email address.' });
  }
  if (validator.isEmpty(req.body.message)) validationErrors.push({ msg: 'Please enter your message.' });

  if (validationErrors.length) {
    req.flash('errors', validationErrors);
    return res.redirect('/contact');
  }
  //neu chu dang nhap thi lay thong tin tu page
  if (!req.user) {
    fromName = req.body.name;
    fromEmail = req.body.email;
  } else {
    fromName = req.user.profile.name || '';
    fromEmail = req.user.email;
  }
  //thiet lap server gui email
  let transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.ID_USER,
      pass: process.env.ID_PASSWORD
    }
  });
  //thiet lap email
  const mailOptions = {
    to: fromEmail,
    from: `${fromName} <${fromEmail}>`,
    subject: 'Contact Form | Hackathon Starter',
    text: req.body.message
  };
  //xu ly gui email
  return transporter.sendMail(mailOptions).then(() => {
    req.flash('success', { msg: 'email has been sent successfully!' });
    res.redirect('/contact')
  }).catch((err) => {
    if (err.message === 'self signed certificate in certificate chain') {
      console.log('WARNING: Self signed certificate in certificate chain. Retrying with the self signed certificate. Use a valid certificate if in production.');
      //gui lai mot lan nua
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
      return transporter.sendMail(mailOptions);
    }
    //cac truong hop khac thi show loi
    console.log('ERROR: Could not send contact email after security downgrade.\n', err);
    req.flash('errors', { msg: 'Error sending the message. Please try again shortly.' });
    return res.redirect('/contact');
    //return false;
  }).then((result) => {
    if (result) {
      req.flash('success', { msg: 'Email has been sent successfully!' });
      return res.redirect('/contact');
    }
  }).catch((err) => {
    console.log('ERROR: Could not send contact email.\n', err);
    req.flash('errors', { msg: 'Error sending the message. Please try again shortly.' });
    return res.redirect('/contact');
  })

}