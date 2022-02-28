const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const bcryptjs = require('bcryptjs');

const userSchema = mongoose.Schema(
    {
        name: {
            type: String,
            required:true
        },
        email: {
            type: String,
            required: true,
            unique:true
        },
        password: {
            type: String,
            required:true
        },
        isAdmin: {
            type: Boolean,
            required: true,
            default:false
        }
    },
    {
       timestamps: true, 
    }
);

// encrypted password
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) {
        next();
    }

    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt)
});

//decrypt password

userSchema.methods.matchPassword = async function (enteredPassword) { 
    //compare the password into database and entered password
    //this.password are called coming from database
    return await bcrypt.compare(enteredPassword, this.password);
}

const User = mongoose.model('User', userSchema);

module.exports = User;