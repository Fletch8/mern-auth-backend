// imports
require('dotenv').config();
const passport = require('passport');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { JWT_SECRET } = process.env;

// Database
const db = require('../models');
const { User } = require('../models');
const { Error } = require('mongoose');

//controllers
const test = (req, res) => {
    res.json({ message: 'User enpoint OK!'})
}

const register = (req, res) => {
    // POST - adding new user to the database
    console.log('======> Inside of /register in contollers/user.js')
    console.log('====> req.bofy')
    console.log(req.body)

    db.User.findOne({ email: req.body.email})
    .then(user => {
        // if email already exist, a user will come back
        if (user){ 
            // send a 400 response
            return res.status(400).json({ message: 'Email already exists'})
        } else {
            // create a new user
            const newUser = new db.User({
                name: req.body.name,
                email: req.body.email,
                password: req.body.password
            })

            // Salt and hash the password before saving the user
            bcrypt.genSalt(10, (err, salt) => {
                if (err) throw Error;

                bcrypt.hash(newUser.password, salt, (err, hash) => {
                    if (err) throw Error;
                    // Change the password in newuser to the hash
                    newUser.password = hash;
                    newUser.save()
                    .then(createdUser => res.json(createdUser))
                    .catch(err => console.log(err))
                })
            })
        }
    })
    .catch(err => console.log('Error finding the user', err))
}

const login = async(req, res) => {
    // POST find user and return the user
    console.log('======> Inside of ^^^/login^^^ in contollers/user.js')
    console.log('====> req.bofy')
    console.log(req.body)

    const foundUser = await db.User.findOne({ email: req.body.email })

    if (foundUser){
        // user is in the DB
        let isMatch = await bcrypt.compare(password, foundUser.password)
        if (isMatch){
            // console.log(isMatch);
            // If user match, send json web token
            // Create a token payload
            // add an 
            const payload = { 
                id: foundUser.id,
                email: foundUser.email,
                name: foundUser.name
            }
    
            jwt.sign(payload, JWT_SECRET, { expiresIn: 3600 }, (err, token) => {
                if (err){
                    res.status(400).json({ message: "Session has ended, please log in again!" })
                }

                const legit = jwt.verify(token, JWT_SECRET, { expiresIn: 60 })    
                console.log('========> legit')
                console.log(legit)
                res.json({ success: true, token: `Bearer ${token}`, userData: legit })
            })

        } else {
            return res.status(400).json({ message: 'Email or Password are inccorect!'})
        }
    }else {
        return res.status(400).json({ message: 'User not Found!' })
    }
}

//Exports
module.exports = {
    test,
    register,
    login,
}