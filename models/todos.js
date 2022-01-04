const mongoose = require("mongoose");
const { User } = require("./user");

const Todos = mongoose.model(
  "Todos",
  new mongoose.Schema(
    {
      title: {
        type: String,
        required: true,
        minlength: 5,
        maxlength: 255,
      },
      description: {
        type: String,
        required: true,
        minlength: 5,
        maxlength: 1024,
      },
      status: {
        type: String,
        enum: {
          values: ["planned", "progress", "done"],
          message: "{VALUE} is not supported",
        },
        default: "planned",
        required: true,
      },
      userId: {
        type: mongoose.ObjectId,
        required: true,
        ref: User,
      },
      color: {
        type: String,
        default: "#ffffff",
        required: true,
      },
    },
    { strict: true, timestamps: true }
  )
);

exports.Todos = Todos;
