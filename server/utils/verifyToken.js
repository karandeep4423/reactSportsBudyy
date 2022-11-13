import jwt from "jsonwebtoken";
import { createError } from "./error.js";

export const verifyToken = async(req, res, next,cb) => {
  const token = req.cookies.access_token;
  if (!token) {
    return next(createError(401, "you are not authenticated"));
  }
  jwt.verify(token, process.env.JWT, (err, user) => {
    if (err) return next(createError(403, "token is invalid"));
    req.user = user;
    cb(user);
    // console.log("token user", req.user)
    // console.log("verify tokken resonse",cb(user))
    cb(user);

  });
};
export const verifyUser = (req, res, next) => {
  verifyToken(req, res, next, (user) => {
    if (user._id === req.user._id && !user.isAdmin) {
      next();
    } else {
     return next(createError(403, "you are not authenticated user"));
    }
  });
};

export const verifyAdmin = (req, res, next) => {
  verifyToken(req, res, next, (user) => {
    if (user.isAdmin==true) {
      next();
    } else {
    return next(createError(403, "you are not authenticated"));
    }
  });
};
