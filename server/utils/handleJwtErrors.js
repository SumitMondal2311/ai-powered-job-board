import jwt from "jsonwebtoken";

const handleJwtErrors = (error, res) => {
  if (error instanceof jwt.JsonWebTokenError) {
    res.status(401).json({ message: "Invalid token" });
    return true;
  }

  if (error instanceof jwt.TokenExpiredError) {
    res.status(401).json({ message: "Expired token" });
    return true;
  }

  if (error instanceof SyntaxError) {
    res.status(401).json({ message: "Token malformed" });
    return true;
  }

  return false;
};

export default handleJwtErrors;
