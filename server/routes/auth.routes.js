import { Router } from "express";
import { login, logout, signup } from "../controllers/auth.controller.js";
import validateAuthencation from "../middlewares/validateAuthentication.js";

const AuthRouter = Router();

AuthRouter.post("/signup", signup);
AuthRouter.post("/login", login);

AuthRouter.use(validateAuthencation);

AuthRouter.post("/logout", logout);

export default AuthRouter;
