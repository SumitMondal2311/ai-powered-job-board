import jwt from "jsonwebtoken";
import prisma from "../configs/prisma.js";
import redis from "../configs/redis.js";
import handleJwtErrors from "../utils/handleJwtErrors.js";

const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET;

const validateAuthencation = async (req, res, next) => {
  try {
    const authHeader = req.headers["authorization"];
    if (!authHeader?.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Invalid access token" });
    }

    const accessToken = authHeader.split(" ")[1];
    const isRevoked = await redis.exists(`blacklist:${accessToken}`);
    if (isRevoked === 1) {
      return res.status(401).json({ message: "Access token revoked" });
    }

    const decoded = jwt.verify(accessToken, ACCESS_TOKEN_SECRET);

    const user = await prisma.user.findUnique({
      where: { id: decoded.uid },
    });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    req.user = user;

    next();
  } catch (error) {
    const tokenError = handleJwtErrors(error, res);
    if (tokenError) return;

    console.error("Error while validating auth: " + error);
    res.status(500).json({ message: "Internal server error" });
  }
};

export default validateAuthencation;
