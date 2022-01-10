const dotenv = require("dotenv");
//const Joi = require('joi');

//Joi.objectId = require('joi-objectid')(Joi);
const mongoose = require("mongoose");
const users = require("./routes/users");
const todos = require("./routes/todos");
const express = require("express");
const bodyParser = require("body-parser");
const cookieSession = require("cookie-session");
const cookieParser = require("cookie-parser");
//const urllib = require('url');
////const path = require('path');
const crypto = require("crypto");

const cors = require("cors");
const app = express();
const PORT = process.env.PORT || 4000;

dotenv.config();

app.listen(PORT, () => console.log(`Listening on port ${PORT}...`));

mongoose
  .connect(process.env.DB_CONNECT)
  .then(() => console.log("Now connected to MongoDB!"))
  .catch((err) => console.error("Something went wrong", err));

app.use(bodyParser.json());
/* ----- session ----- */
app.use(
  cookieSession({
    name: "session",
    keys: [crypto.randomBytes(32).toString("hex")],
    // Cookie Options
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
  })
);
app.use(cookieParser());
//app.use(cors())
app.use(express.json(), cors({ credentials: true, origin: true }));

app.use("/users", users);
app.use("/todos", todos);
