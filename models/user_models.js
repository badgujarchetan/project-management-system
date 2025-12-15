import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "crypto";

const userSchema = new mongoose.Schema(
  {
    avatar: {
      type: {
        url: String,
        localPath: String,
      },
      default: {
        url: "https://placehold.co/200x200",
        localPath: "",
      },
    },
    username: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      lowercase: true,
      index: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      lowercase: true,
      index:true
    },
    fullName: {
      type: String,
      // required: true,
      trim: true,
    },
    password: {
      type: String,
      required: [true, "Password is required"],
      
    },
    isEmailVerified: {
      type: Boolean,
      default: false,
    },
    refreshToken: String,
    forgotPasswordToken: String,
    forgotPasswordTokenExpiry: Date,
    emailVerificationToken: String,
    emailVerificationTokenExpiry: Date,
  },
  { timestamps: true }
);

userSchema.pre("save", async function () {
  if (!this.isModified("password")) return;

  this.password = await bcrypt.hash(this.password, 10);
});


userSchema.methods.isPasswordMatched = async function (enteredPassword) {
  return bcrypt.compare(enteredPassword, this.password);
};

userSchema.methods.generateAccessToken = function () {
  return jwt.sign(
    { _id: this._id, email: this.email },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn: process.env.ACCESS_TOKEN_EXPIRES_IN }
  );
};

userSchema.methods.generateRefreshToken = function () {
  return jwt.sign(
    { _id: this._id, email: this.email },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn: process.env.REFRESH_TOKEN_EXPIRES_IN }
  );
};

userSchema.methods.generateTemporaryToken = function () {
  const unhashToken = crypto.randomBytes(20).toString("hex");

  const hashToken = crypto
    .createHash("sha256")
    .update(unhashToken)
    .digest("hex");

  const tokenExpiry = Date.now() + 20 * 60 * 1000; //20 min

  return { unhashToken, hashToken, tokenExpiry };
};

const User = mongoose.model("User", userSchema);
export default User;
