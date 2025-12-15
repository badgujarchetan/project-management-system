import Mailgen from "mailgen";
import nodemailer from "nodemailer";

const sendMail = async (options) => {
  if (!options?.mailContent || !options.mailContent.body) {
    throw new Error("Mail content missing or invalid");
  }

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

  const mailOptions = {
    from: `"Task Manager" <${process.env.EMAIL_USER}>`,
    to: options.email,
    subject: options.subject,
    text: emailText,
    html: emailHtml,
  };

  await transporter.sendMail(mailOptions);
};


const emailVerificationMailgenContent = (username, verificationUrl) => {
  return {
    body: {
      name: username,
      intro: "Welcome to Task Manager 🎉 We’re excited to have you onboard.",
      action: {
        instructions:
          "To verify your email address and activate your account, click the button below:",
        button: {
          color: "#22BC66",
          text: "Verify Email",
          link: verificationUrl,
        },
      },
      outro:
        "If you did not create this account, you can safely ignore this email.",
    },
  };
};


const forgotPasswordMailgenContent = (username, resetPasswordUrl) => {
  return {
    body: {
      name: username,
      intro:
        "You recently requested to reset your password for your Task Manager account.",
      action: {
        instructions:
          "Click the button below to reset your password. This link will expire soon.",
        button: {
          color: "#DC4D2F",
          text: "Reset Password",
          link: resetPasswordUrl,
        },
      },
      outro:
        "If you did not request a password reset, please ignore this email.",
    },
  };
};

export {
  sendMail,
  emailVerificationMailgenContent,
  forgotPasswordMailgenContent,
};
