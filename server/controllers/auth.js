import User from "../models/user.js";
import { createError } from "../utils/error.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

export const register = async (req, res, next) => {
  try {
    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(req.body.password, salt);
    const newUser = new User({
      username: req.body.username,
      email: req.body.email,
      password: hash,
    });
    await newUser.save();
    // res.status(200).send("user has been registered successfully");
    const user = await User.findOne({ username: req.body.username });
  
    const token = jwt.sign(
      { id: user._id, isAdmin: user.isAdmin },
      process.env.JWT
    );
    // destrcuturing the details for frontend
    const { password, isAdmin, ...otherDetails } = user._doc;
    //saving token in cookies
      res.cookie("access_token", token , {
        httpOnly: true,
      })
      .status(200)
      //sending data to frontend
      .json({ details: { ...otherDetails }, isAdmin });

  } catch (err) {
    next(err);
  }
};

export const login = async (req, res, next) => {
  try {
    const user = await User.findOne({ username: req.body.username });
    if (!user) return next(createError(404, "User not found"));

    const isPasswordCorrect = await bcrypt.compare(
      req.body.password,
      user.password
    );
    if (!isPasswordCorrect)
      return next(createError(400, "Password or email incorrect  "));
//creating token in cookies
    const token = jwt.sign(
      { id: user._id, isAdmin: user.isAdmin },
      process.env.JWT
    );
    // destrcuturing the details for frontend
    const { password, isAdmin, ...otherDetails } = user._doc;
    //saving token in cookies
      res.cookie("access_token", token , {
        httpOnly: true,
      })
      .status(200)
      //sending data to frontend
      .json({ details: { ...otherDetails }, isAdmin });
  } catch (err) {
    next(err);
  }
};

export const logout = async (req, res, next) => {
  try {
    await res.clearCookie("access_token",{path:"/"});
    res.status(200).json("cookie deleted");
  } catch (err) {
    next(err);
  }
 
};
