
const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  service: 'gmail', 
  auth: {
    user: process.env.EMAIL_USERNAME,
    pass: process.env.EMAIL_PASSWORD,
  },
});

const mailer = {
  sendVerificationEmail: async (to, verificationToken, username) => {
    const verificationURL = `${process.env.PAGE_RECOVER_URL}/verifyUser.html?token=${verificationToken}`;
    console.log('token : ', verificationToken);
    const mailOptions = {
      from: `Standard Cuts Support Team <${process.env.EMAIL_USERNAME}>`,
      to,
      subject: 'Please verify your email address',
      html: `
        <h2>Welcome, ${username}!</h2>
        <p>Thanks for signing up. We are thrilled to have you. Please verify your email by clicking the link below:</p>
        <a href="${verificationURL}">Verify Email</a>
        <p>If you didn't sign up, please ignore this email.</p>
      `,
    };

     await transporter.sendMail(mailOptions);
  },

  sendPasswordResetEmail: async (to, resetToken, username) => {
  const resetURL = `${process.env.PAGE_RECOVER_URL}/resetPassword.html?token=${resetToken}`;
  console.log('Password Reset URL:', resetURL);

  const mailOptions = {
    from: `Standard Cuts Support Team <${process.env.EMAIL_USERNAME}>`,
    to,
    subject: 'Password Reset Request',
    html: `
      <h2>Hello, ${username}</h2>
      <p>We received a request to reset your password. Please click the link below to reset it:</p>
      <a href="${resetURL}">Reset Password</a>
      <p>If you did not request a password reset, please ignore this email.</p>
      <p>This link will expire in 15 minutes.</p>
    `,
  };

  console.log('Mail options:', mailOptions);
  await transporter.sendMail(mailOptions);
},

};

module.exports = mailer;
