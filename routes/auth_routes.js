import { Router } from "express";
import {
  changeCurrentPassword,
  emailVerify,
  forgotPassword,
  getCurrentuser,
  loginUserController,
  logOutUser,
  refreshAccessToken,
  registerUserController,
  resetForgotPassword,
} from "../controllers/auth_controller.js";
import { validateMiddleware } from "../middlewares/validator_middlewares.js";
import {
  registeUserValidator,
  loginUserValidator,
  userforgotPasswordValidator,
  resetForgotPasswordValidator,
  userchangecurrenrPasswordValidator,
} from "../validators/index.js";
import { authJWTVerify } from "../middlewares/auth_middlewares.js";
const router = Router();

router.post(
  "/register",

  registeUserValidator(),
  validateMiddleware,
  registerUserController
);

router.post(
  "/login",
  loginUserValidator(),
  validateMiddleware,
  loginUserController
);

router.get("/email-verify/:emailVerifyToken", emailVerify);

router.post("/refreshAccessToken", refreshAccessToken);
router.post(
  "/forgotPassword",
  userforgotPasswordValidator(),
  validateMiddleware,
  forgotPassword
);
router.post(
  "/resetForgotPassword/:resetToken",
  resetForgotPasswordValidator(),
  validateMiddleware,
  resetForgotPassword
);
router.post(
  "/changeCurrentPassword",
  userchangecurrenrPasswordValidator(),
  validateMiddleware,
  changeCurrentPassword
);
router.get("/logout", authJWTVerify, logOutUser);
router.get("/current-user", authJWTVerify, getCurrentuser);

export default router;
