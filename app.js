require("dotenv").config();
require("./config/database").connect();
const express = require("express");
const bcrypt = require("bcrypt");
const app = express();
const jwt = require("jsonwebtoken");
const auth = require("./middleware/auth");

app.use(express.json());

// Logic goes here

// importing user context
const User = require("./model/user");
const { verifyJwtToken } = require("./helper");

// Register
app.post("/register", async (req, res) => {
  // Our register logic starts here
  try {
    // Get user input
    const { first_name, last_name, email, password } = req.body;
    console.log("req.body", req.body);

    // Validate user input
    if (!(email && password && first_name && last_name)) {
      res.status(400).send("All input is required");
    }

    // check if user already exist
    // Validate if user exist in our database
    const oldUser = await User.findOne({ email });

    if (oldUser) {
      return res.status(409).send("User Already Exist. Please Login");
    }

    const salt = await bcrypt.genSaltSync(10);

    //Encrypt user password
    encryptedPassword = await bcrypt.hash(password, salt);

    // Create user in our database
    const user = await User.create({
      first_name,
      last_name,
      email: email.toLowerCase(), // sanitize: convert email to lowercase
      password: encryptedPassword,
    });

    // Create token
    const token = jwt.sign({ user_id: user._id, email }, process.env.TOKEN_KEY, {
      expiresIn: "2h",
    });

    const refreshToken = jwt.sign({ user_id: user._id, email }, process.env.REFRESH_TOKEN_KEY, {
      expiresIn: "2h",
    });
    // save user token
    user.token = token;
    user.refreshToken = refreshToken;
    console.log("12312312312 user", user);

    // return new user
    res.status(201).json(user);
  } catch (err) {
    console.log(err);
  }
  // Our register logic ends here
});

// Login
app.post("/login", async (req, res) => {
  // Our login logic starts here
  try {
    // Get user input
    const { email, password } = req.body;

    // Validate user input
    if (!(email && password)) {
      res.status(400).send("All input is required");
    }
    // Validate if user exist in our database
    const user = await User.findOne({ email });

    if (user && (await bcrypt.compare(password, user.password))) {
      const token = jwt.sign({ user_id: user._id, email }, process.env.TOKEN_KEY, {
        expiresIn: "2h",
      });

      const refreshToken = jwt.sign({ user_id: user._id, email }, process.env.REFRESH_TOKEN_KEY, {
        expiresIn: "2h",
      });

      user.token = token;
      user.refreshToken = refreshToken;
      res.status(200).json(user);
    }
    res.status(400).send("Invalid Credentials");
  } catch (err) {
    console.log(err);
  }
});

app.post("/refresh_token", async (req, res) => {
  const { refreshToken } = req.body;
  if (refreshToken) {
    try {
      const data = await verifyJwtToken(refreshToken, process.env.REFRESH_TOKEN_KEY);
      console.log("data");
      const token = jwt.sign(
        { user_id: data.user_id, email: data.email },
        process.env.REFRESH_TOKEN_KEY,
        {
          expiresIn: "2h",
        }
      );
      const response = {
        token,
      };
      res.status(200).json(response);
    } catch (err) {
      console.error(err);
      res.status(403).json({
        message: "Invalid refresh token",
      });
    }
  } else {
    res.status(400).json({
      message: "Invalid request",
    });
  }
});

app.post("/welcome", auth, (req, res) => {
  res.status(200).send("Welcome 🙌 ");
});

module.exports = app;
