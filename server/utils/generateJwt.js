import jwt from "jsonwebtoken";

const generateJwt = ({ sid, uid, secret, expiresIn }) => {
  return jwt.sign({ sid, uid }, secret, { expiresIn });
};

export default generateJwt;
