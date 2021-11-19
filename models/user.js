const Joi = require('joi');
const mongoose = require('mongoose');

const User = mongoose.model('User', new mongoose.Schema({
    email: {
        type: String,
        required: true,
        minlength: 5,
        maxlength: 255,
        unique: true
    },
    password: {
        type: String,
        required: false,
        minlength: 5,
        maxlength: 1024
    },
}, {strict: false}));

function validateUser(user) {
    const schema = Joi.object({
        email: Joi.string().min(5).max(255).required().email(),
        password: Joi.string().min(5).max(255)
    });

    return schema.validate(user);
}

const loginValidate = Joi.object({
    email: Joi.string().min(5).max(255).required().email(),
    password: Joi.string().min(5).max(255).required()
})


exports.User = User;
exports.validate = validateUser;
exports.loginValidate = loginValidate;