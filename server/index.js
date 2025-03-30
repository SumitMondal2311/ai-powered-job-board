import { config } from "dotenv";
config();

import validatePrivateVariables from "./lib/validatePrivateVariables.js";
validatePrivateVariables();

import cookieParser from "cookie-parser";
import cors from "cors";
import express from "express";
import helmet from "helmet";
import morgan from "morgan";
import startBackend from "./lib/startBackend.js";
import AuthRouter from "./routes/auth.routes.js";

const app = express();

app.use(express.json());
app.use(cookieParser());
app.use(cors({ origin: process.env.FRONTEND_URL, credentials: true }));
app.use(morgan("dev"));
app.use(helmet());

app.use("/auth", AuthRouter);

await startBackend(app);
