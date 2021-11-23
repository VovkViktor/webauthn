const mongoose = require("mongoose");

const AuthnKey = mongoose.model(
  "Authnkey",
  new mongoose.Schema(
    {
      userId: {
        type: mongoose.ObjectId,
        required: true,
      },
      key: {
        type: Object,
        required: true,
      },
    },
    { timestamps: true }
  )
);

module.exports = {
  AuthnKey,
};
