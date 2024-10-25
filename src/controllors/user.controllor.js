import { asyncHandler } from "../utils//asyncHandler.js";
import { ApiError } from "../utils/AipError.js";
import { User } from "../models/user.model.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken";
import { application } from "express";
import nodemailer from "nodemailer";

const generateAccessAndRefreshToken = async (userId) => {
  const user = await User.findById(userId);

  const accessToken = user.generateAccessToken();
  const refreshToken = user.generateRefreshToken();

  user.refreshToken = refreshToken;
  user.save({ validateBeforeSave: false });

  return { accessToken, refreshToken };
};

// const registerUser = asyncHandler(async (req, res) => {
//   const { fullName, email, username, password } = req.body;

//   if (
//     [fullName, email, username, password].some((field) => field?.trim() === "")
//   ) {
//     throw new ApiError(400, "all fileds are required");
//   }

//   const existedUser = await User.findOne({
//     $or: [{ username }, { email }],
//   });

//   if (existedUser) {
//     throw new ApiError(409, "user with email or username already exists");
//   }

//   const user = await User.create({
//     fullName,
//     email,
//     password,
//     username: username,
//   });~~~
//   console.log("good");

//   console.log(user);

//   const createdUser = await User.findById(user._id).select(
//     "-password -refreshToken"
//   );

//   if (!createdUser) {
//     throw new ApiError(500, "something went worng while registering the user");
//   }

//   return res
//     .status(201)
//     .json(new ApiResponse(200, createdUser, "user registered successfully"));
// });

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Registration controller with OTP
// Registration Controller
const registerUser = asyncHandler(async (req, res) => {
  const { fullName, email, username, password } = req.body;

  if (
    [fullName, email, username, password].some((field) => field?.trim() === "")
  ) {
    throw new ApiError(400, "All fields are required");
  }

  const existedUser = await User.findOne({ $or: [{ username }, { email }] });
  if (existedUser) {
    throw new ApiError(409, "User with email or username already exists");
  }

  // Create user with OTP fields and set verified as false
  const otp = generateOTP();
  const otpExpires = Date.now() + 10 * 60 * 1000; // OTP valid for 10 minutes

  const user = await User.create({
    fullName,
    email,
    password,
    username,
    otp,
    otpExpires,
    verified: false
  });

  console.log(user);
  

  // Send OTP email
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: "shantanuhardia1605@gmail.com",
      pass: 'luxz eatm yqgl cdzu'
    },
  });

  const mailOptions = {
    from: "shantanuhardia1605@gmail.com",
    to: email,
    subject: "Your OTP Code",
    text: `Your OTP code is ${otp}`,
    html: `<b>Your OTP code is ${otp}</b>`,
  };

  transporter.sendMail(mailOptions, (error) => {
    if (error) {
      throw new ApiError(500, "Failed to send OTP");
    }
    console.log(`OTP sent: ${otp}`);
  });

  return res
    .status(201)
    .json(
      new ApiResponse(
        200,
        { userId: user._id },
        "User registered, please verify OTP"
      )
    );
});

// OTP Verification Controller
const verifyOTP = asyncHandler(async (req, res) => {
  const { userId, otp } = req.body;

  const user = await User.findById(userId);
  if (!user || user.otpExpires < Date.now() || user.otp !== otp) {
    throw new ApiError(400, "Invalid or expired OTP");
  }

  // Set user as verified and clear OTP fields
  user.verified = true;
  user.otp = undefined;
  user.otpExpires = undefined;
  await user.save();

  const createdUser = await User.findById(user._id).select(
    "-password -refreshToken"
  );
  console.log(createdUser);
  
  return res
    .status(200)
    .json(
      new ApiResponse(
        200,
        createdUser,
        "OTP verified, user registered successfully"
      )
    );
});

const loginUser = asyncHandler(async (req, res) => {
  // getting the data from request

  const { email, password, username } = req.body;

  if (!(username || email)) {
    throw new ApiError(404, "username or email is required");
  }

  const user = await User.findOne({
    $or: [{ username }, { email }],
  });

  if (!user) {
    throw new ApiError(404, "user dose not exists");
  }

  const isPasswordValid = await user.isPasswordCorrect(password);

  if (!isPasswordValid) {
    throw new ApiError(401, "password is incorrect");
  }

  const { accessToken, refreshToken } = await generateAccessAndRefreshToken(
    user._id
  );

  const loggedInUser = await User.findById(user._id).select(
    "-password -refreshToken"
  );

  const options = {
    httpOnly: true,
    secure: true,
  };

  return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
      new ApiResponse(
        200,
        {
          user: loggedInUser,
          accessToken,
          refreshToken,
        },
        "user loggedIn successfully"
      )
    );
});

const logOutUser = asyncHandler(async (req, res) => {
  console.log("user logout successfully");

  // forgoted to add the await in db operation ,got a bug here
  await User.findByIdAndUpdate(
    req.user?._id,
    {
      $set: {
        refreshToken: undefined,
        // alternatively this will also work -> refreshToken: 1
      },
    },
    {
      new: true,
    }
  );

  const options = {
    httpOnly: true,
    secure: true,
  };

  res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "user logged out"));
});

const refreshAccessToken = asyncHandler(async (req, res) => {
  const incomingrefreshToken =
    req.cookies.refreshToken || req.body.refreshToken;

  if (!incomingrefreshToken) {
    throw new ApiError(401, "unauthorized access");
  }

  try {
    const decodedtoken = jwt.verify(
      incomingrefreshToken,
      process.env.REFRESH_TOKEN_SECRET
    );

    const user = await User.findById(decodedtoken?._id);

    if (!user) {
      throw new ApiError(401, "invalid refresh Token");
    }

    if (incomingrefreshToken !== user?.refreshToken) {
      throw new ApiError(401, "Refresh Token is expired or used");
    }

    const { accessToken, newRefreshToken } =
      await generateAccessAndRefreshToken(user?._id);

    const options = {
      httpOnly: true,
      secure: true,
    };

    return res
      .status(200)
      .cookie("accessToken", accessToken, options)
      .cookie("refreshToken", newRefreshToken, options)
      .json(
        new ApiResponse(
          200,
          { accessToken, refreshToken: newRefreshToken },
          "Access Token refreshed"
        )
      );
  } catch (error) {
    throw new ApiError(401, error?.message || "Invalid Refresh Token");
  }
});

const changeCurrentPassword = asyncHandler(async (req, res) => {
  const { oldPassword, newPassword } = req.body;

  const user = await User.findById(req.user?._id);

  const isPasswordCorrect = await user.isPasswordCorrect(oldPassword);

  if (!isPasswordCorrect) {
    throw new ApiError(400, "inncorrect old passsword");
  }

  user.password = newPassword;

  await user.save({ validateBeforeSave: false });

  return res
    .status(200)
    .json(new ApiResponse(200, {}, "password changed successfully"));
});

const getCurrentUser = asyncHandler(async (req, res) => {
  return res
    .stauts(200)
    .json(new ApiResponse(200, req.user, "user fetched successfully"));
});

const updateAccountDetails = asyncHandler(async (req, res) => {
  const { fullName, email } = req.body;

  if (!fullName || !email) {
    throw new ApiError(401, "all fields are required");
  }

  const user = await User.findByIdAndUpdate(
    req.user?._id,
    {
      $set: {
        fullName,
        email: email,
      },
    },
    {
      new: true,
    }
  ).select("-password");

  return res
    .status(200)
    .json(new ApiResponse(200, user, "account details updated successfully"));
});

export {
  registerUser,
  verifyOTP,
  loginUser,
  logOutUser,
  refreshAccessToken,
  changeCurrentPassword,
  getCurrentUser,
  updateAccountDetails,
};
