const mongoose = require("mongoose");
const validator = require("validator");
const bcrypt = require("bcryptjs");
const { use } = require("../routes/authRoutes");
const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: [true, "Please enter an email"],
    lowercase: true,
    unique: true,
    trim: true,
    validate: [
      (val) => {
        return validator.isEmail(val);
      },
      "Please enter a valid email",
    ],
  },
  password: {
    type: String,
    required: [true, "Please enter an email"],
    minlength: [6, "Minimum password length is 6"],
  },
});

userSchema.pre("save", async function (next) {
  const user = this;
  const salt = await bcrypt.genSalt();
  user.password = await bcrypt.hash(user.password, salt);
  next();
});

userSchema.statics.login = async function (email, password) {
  const user = await this.findOne({ email });

  if (user) {
    const auth = await bcrypt.compare(password, user.password);
    if (auth) return user;
    else throw Error("Incorrect Password");
  } else {
    throw Error("Incorrect Email");
  }
};

const User = new mongoose.model("user", userSchema);

module.exports = User;
