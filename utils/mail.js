import Mailgen from "mailgen";
import nodemailer from "nodemailer";

const sendMail = async (options) => {
  const mailGenerator = new Mailgen({
    theme: "default",
    product: {
      name: "Task Manager",
      link: "http://taskmanagerlink.com",
    },
  });
  const emailText = mailGenerator.generatePlaintext(options.mailContent);
  const emailHtml = mailGenerator.generate(options.mailContent);

  const transporter = nodemailer.createTransport({
    host: process.env.MAILTRAP_HOST,
    port: process.env.MAILTRAP_PORT,
    auth: {
      user: process.env.MAILTRAP_USER,
      pass: process.env.MAILTRAP_PASSWORD,
    },
  });

  const Mail = {
    from: `"Task Manager" <${process.env.EMAIL_USER}>`,
    to: options.email,
    subject: options.subject,
    html: emailHtml,
    text: emailText,
  };

  try {
    await transporter.sendMail(Mail);
  } catch (error) {
    console.error("Email service failed ", error);
  }
};

const emailVerificationMailgenContent = (username, verificationUrl) => {
  return {
    body: {
      name: username,

      intro: "Welcome to our App 🎉 We're excited to have you on board.",

      action: {
        instructions:
          "To complete your registration and verify your email address, please click the button below:",
        button: {
          color: "#22BC66",
          text: "Verify Email",
          link: verificationUrl,
        },
      },

      outro:
        "If you did not create this account, you can safely ignore this email.",

      signature: "Thanks",
    },
  };
};

const forgotPasswordMailgenContent = (username, resetPasswordUrl) => {
  return {
    body: {
      name: username,

      intro: "You recently requested to reset your password for your account.",

      action: {
        instructions:
          "Click the button below to reset your password. This link is valid for a limited time.",
        button: {
          color: "#DC4D2F",
          text: "Reset Password",
          link: resetPasswordUrl,
        },
      },

      outro:
        "If you did not request a password reset, please ignore this email or contact support if you have concerns.",

      signature: "Thanks",
    },
  };
};

export {
  emailVerificationMailgenContent,
  forgotPasswordMailgenContent,
  sendMail,
};
