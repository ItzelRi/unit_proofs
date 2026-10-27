// models/user.js

const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const config = require('../config/config').get(process.env.NODE_ENV);

const SALT_I = 10;

const userSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        trim: true,
        unique: true,
        lowercase: true
    },
    password: {
        type: String,
        required: true,
        minlength: 6
    },
    firstname: {
        type: String,
        maxlength: 100,
        trim: true
    },
    lastname: {
        type: String,
        maxlength: 100,
        trim: true
    },
    token: {
        type: String
    }
}, {timestamps: true});

// Encriptar la contraseña antes de guardar el usuario
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next() 
        try{
    const salt = await bcrypt.genSalt(SALT_I)
        this.password = await bcrypt.hash(this.password, salt);
            next();
        } catch (error) {
            next(error);
    }
});

// Método para comparar contraseñas en el Login
userSchema.methods.comparepassword = async function (candidatePassword) {
     return bcrypt.compare(candidatePassword, this.password)
};

// Generar Token JWT al iniciar sesión
userSchema.methods.generateToken = async function () {
    const token = jwt.sign({ _id:this._id.toHexString() }, config.SECRET);
    this.token =  token;
    await this.save()
    return null;
};

// Método estático para validar un usuario mediante su Token
userSchema.statics.findByToken = async function (token) {
    try {
        const decode = jwt.verify(token, config.SECRET)
        return await this.findOne({ _id: decode._id, token });
    } catch (error) {
        return error
    }
};

// Eliminar token en el Logout
userSchema.methods.deleteToken = async function () {
    return await this.updateOne({ $unset: { token: 1 } })
    };

const User = mongoose.model('User', userSchema);

module.exports = User;