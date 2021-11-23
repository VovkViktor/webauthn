const mongoose = require("mongoose");

const AuthnKey = mongoose.model(
  "Authnkey",
  new mongoose.Schema({
    userId: {
      type: mongoose.ObjectId,
      required: true,
    },
    key: {
      type: Object,
      required: true,
    },
    dateCreate: {
      type: Number,
      required: true,
      default: new Date().getTime(),
    },
  })
);

module.exports = {
  AuthnKey,
};
