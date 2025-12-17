import { body } from "express-validator";

const registeUserValidator = () => {
  return [
    body("email")
      .trim()
      .notEmpty()
      .withMessage("email is required")
      .isEmail()
      .withMessage("email is invalid")
      .normalizeEmail()
      .isLength({ max: 100 })
      .withMessage("email must be at most 100 characters long")
      .bail()
      .custom((value) => {
        if (value.endsWith(".test")) {
          throw new Error("test emails are not allowed");
        }
        return true;
      }),

    body("username")
      .trim()
      .notEmpty()
      .withMessage("username is required")
      .isLowercase()
      .withMessage("username must be lowercase")
      .isLength({ min: 3 })
      .withMessage("username must be at least 3 characters long")
      .isLength({ max: 30 })
      .withMessage("username must be at most 30 characters long")
      .matches(/^[a-z0-9_]+$/)
      .withMessage(
        "username can only contain lowercase letters, numbers, and underscores"
      )
      .not()
      .isEmail()
      .withMessage("username cannot be an email"),
    body("password")
      .trim()
      .notEmpty()
      .withMessage("password is required")
      .isLength({ min: 6 })
      .withMessage("password must be at least 6 characters long"),

    body("fullName")
      .optional()
      .trim()
      .isLength({ max: 100 })
      .withMessage("fullName must be at most 100 characters long"),
  ];
};

const loginUserValidator = () => {
  return [
    body("email")
      .trim()
      .notEmpty()
      .withMessage("email is required")
      .isEmail()
      .withMessage("email is invalid")
      .normalizeEmail(),
    body("password")
      .trim()

      .notEmpty()
      .withMessage("password is required"),
  ];
};

const userchangecurrenrPasswordValidator = () => {
  return [
    body("oldPassword")
      .trim()
      .notEmpty()
      .withMessage("currentPassword is required"),
    body("newPassword")
      .trim()
      .notEmpty()
      .withMessage("newPassword is required")
      .isLength({ min: 6 })
      .withMessage("newPassword must be at least 6 characters long"),
  ];
};

const userforgotPasswordValidator = () => {
  return [
    body("email")
      .trim()
      .notEmpty()
      .withMessage("email is required")
      .isEmail()
      .withMessage("email is invalid")
      .normalizeEmail(),
  ];
};

const resetForgotPasswordValidator = () => {
  return [
    body("newPassword")
      .trim()
      .notEmpty()
      .withMessage("newPassword is required")
      .isLength({ min: 6 })
      .withMessage("newPassword must be at least 6 characters long"),
  ];
};

export {
  registeUserValidator,
  loginUserValidator,
  userchangecurrenrPasswordValidator,
  userforgotPasswordValidator,
  resetForgotPasswordValidator,
};
