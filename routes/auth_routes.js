import { Router } from "express";
import { registerUserController } from "../controllers/auth_controller.js";
const router = Router();

router.post("/register", registerUserController);
export default router;
