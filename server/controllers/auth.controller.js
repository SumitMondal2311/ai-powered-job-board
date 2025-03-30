import bcrypt from "bcryptjs";
import { randomBytes } from "crypto";
import jwt from "jsonwebtoken";
import { setTimeout } from "timers/promises";
import prisma from "../configs/prisma.js";
import redis from "../configs/redis.js";
import { loginSchema, signupSchema } from "../lib/schemas.js";
import generateJwt from "../utils/generateJwt.js";
import handleJwtErrors from "../utils/handleJwtErrors.js";

const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET;
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET;

const ACCESS_TOKEN_EXPIRY = 60 * 15;
const REFRESH_TOKEN_EXPIRY = 60 * 60 * 24;

const signup = async (req, res) => {
  try {
    const userAgent = req.headers["user-agent"];
    if (!userAgent) {
      return res.status(400).json({ message: "Invalid UA header" });
    }

    const { success, error, data } = signupSchema.safeParse(req.body);
    if (!success) {
      return res.status(400).json({ message: error.issues[0].message });
    }

    const { fullName, email, password, role } = data;

    const isUserExists = await prisma.user.findUnique({
      where: { email },
    });

    if (isUserExists) {
      await setTimeout(1000);
      return res.status(409).json({ message: "User already exists" });
    }

    const emailProviders = [
      "gmail.com",
      "yahoo.com",
      "outlook.com",
      "hotmail.com",
    ];

    const domain = email.split("@")[1];
    const isOrdinaryEmail = emailProviders.includes(domain);

    if (role === "RECRUITER" && isOrdinaryEmail) {
      return res.status(400).json({ message: "Require company email" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await prisma.user.create({
      data: { fullName, email, password: hashedPassword, role },
    });

    const accessToken = generateJwt({
      uid: newUser.id,
      secret: ACCESS_TOKEN_SECRET,
      expiresIn: ACCESS_TOKEN_EXPIRY,
    });

    const sessionId = randomBytes(32).toString("hex");
    const sessionData = {
      userId: newUser.id,
      userAgent,
      token: accessToken,
      expiresAt: Date.now() + REFRESH_TOKEN_EXPIRY,
    };

    await redis.set(`session:${sessionId}`, JSON.stringify(sessionData), {
      ex: REFRESH_TOKEN_EXPIRY,
    });

    const refreshToken = generateJwt({
      uid: newUser.id,
      sid: sessionId,
      secret: REFRESH_TOKEN_SECRET,
      expiresIn: REFRESH_TOKEN_EXPIRY,
    });

    res.cookie("__refresh_token__", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: REFRESH_TOKEN_EXPIRY * 1000,
      path: "/",
      sameSite: "lax",
    });

    res.status(201).json({ accessToken, message: "Signed up successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error" });
  }
};

const login = async (req, res) => {
  try {
    const userAgent = req.headers["user-agent"];
    if (!userAgent) {
      return res.status(400).json({ message: "Invalid UA header" });
    }

    const { success, error, data } = loginSchema.safeParse(req.body);
    if (!success) {
      return res.status(400).json({ message: error.issues[0].message });
    }

    const { email, password } = data;

    const user = await prisma.user.findUnique({
      where: { email },
    });

    if (!user) {
      await setTimeout(1000);
      return res.status(401).json({ message: "Invalid email or password" });
    }

    const isMatched = await bcrypt.compare(password, user.password);
    if (!isMatched) {
      await setTimeout(1000);
      return res.status(401).json({ message: "Invalid email or password" });
    }

    const accessToken = generateJwt({
      uid: user.id,
      secret: ACCESS_TOKEN_SECRET,
      expiresIn: ACCESS_TOKEN_EXPIRY,
    });

    const [cursor, keys] = await redis.scan(0, { match: "session:*" });
    if (keys.length > 0) {
      const sessions = await redis.mget(keys);
      for (const session of sessions) {
        if (!sessions) continue;

        const sessionData = session;
        if (sessionData.userAgent === userAgent) {
          return res.status(403).json({ message: "Already logged in" });
        }
      }
    }

    const sessionId = randomBytes(32).toString("hex");
    const sessionData = {
      userId: user.id,
      userAgent,
      token: accessToken,
      expiresAt: Date.now() + REFRESH_TOKEN_EXPIRY,
    };

    await redis.set(`session:${sessionId}`, JSON.stringify(sessionData), {
      ex: REFRESH_TOKEN_EXPIRY,
    });

    const refreshToken = generateJwt({
      sid: sessionId,
      uid: user.id,
      secret: REFRESH_TOKEN_SECRET,
      expiresIn: REFRESH_TOKEN_EXPIRY,
    });

    res.cookie("__refresh_token__", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: REFRESH_TOKEN_EXPIRY * 1000,
      path: "/",
      sameSite: "lax",
    });

    res.status(200).json({ accessToken, message: "Logged in successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error" });
  }
};

const logout = async (req, res) => {
  try {
    const refreshToken = req.cookies["__refresh_token__"];
    if (!refreshToken) {
      return res.status(401).json({ message: "Missing refresh token" });
    }

    const decoded = jwt.verify(refreshToken, REFRESH_TOKEN_SECRET);

    const existingSessionId = decoded.sid;
    const existingSessionKey = `session:${existingSessionId}`;

    const session = await redis.get(existingSessionKey);
    if (!session) {
      return res.status(404).json({ message: "Session not found" });
    }

    const accessToken = session.token;

    await Promise.all([
      await redis.set(`blacklist:${accessToken}`, "revoked", { ex: 60 * 15 }),
      await redis.del(existingSessionKey),
    ]);

    res.cookie("__refresh_token__", "", {
      expires: new Date(0),
      httpOnly: true,
    });

    res.status(200).json({ message: "Logged out successfully" });
  } catch (error) {
    const hasError = handleJwtErrors(error, res);
    if (hasError) return;

    console.error(error);
    res.status(500).json({ message: "Internal server error" });
  }
};

export { login, logout, signup };
