const User = require('../models/user')
const AWS = require('aws-sdk')
const jwt = require('jsonwebtoken')
const expressJwt = require('express-jwt')
const shortId = require('shortid')
const _ = require('lodash')
const { registerEmailParams, forgotPasswordEmailParams } = require('../helpers/email')

AWS.config.update({
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    region: process.env.AWS_REGION
})

const ses = new AWS.SES({ apiVersion: '2010-12-01' })

exports.register = (req, res) => {
    const { name, email, password } = req.body

    User.findOne({ email }).exec((err, user) =>{
        if (user) {
            return res.status(400).json({
                error: 'Email is taken'
            })
        }
        const token = jwt.sign({ name, email, password }, process.env.JWT_ACCOUNT_ACTIVATION, {
            expiresIn: '10m'
        })

        const params = registerEmailParams(email, token)

        const sendEmailOnRegister = ses.sendEmail(params).promise()

        sendEmailOnRegister
            .then(data => {
                console.log('email submitted to SES', data)
                res.json({
                    message: `Email has been sent to ${email}, Follow the instructions to complete your registration`
                })
            })
            .catch(error => {
                console.log('ses email on register', error)
                res.json({
                    error: `We could not verify your email. Please try again`
                })
            })
    })

}

exports.registerActivate = (req, res) => {
    const { token } = req.body
    // console.log({ token })

    jwt.verify(token, process.env.JWT_ACCOUNT_ACTIVATION, function(err, decoded) {

        if (err) {
            console.log(err)
            if (err.name === 'TokenExpiredError') {
                return res.status(401).json({
                    error: 'Expired link. Try again.'
                })
            }

            return res.status(500).json({
                error: err
            })
        }

        const { name, email, password } = decoded
        const username = shortId.generate()

        User.findOne({ email }).exec((err, user) => {
            if (user) {
                return res.status(401).json({
                    error: 'Email is taken'
                })
            }

            // register new user
            const newUser = new User({ username, name, email, password })
            newUser.save((err, result) => {
                if (err) {
                    return res.status(401).json({
                        error: 'Error saving user in database. Try later'
                    })
                }
                return res.json({
                    message: 'Registration success. Please login.'
                })
            })
        })
    })
}

exports.login = (req, res) => {
    const { email, password } = req.body
    
    User.findOne({email}).exec((err, user) => {
        if (!user || err) {
            return res.status(400).json({
                message: 'User with that email does not exist. Please register.'
            })
        }

        // authenticate
        if(!user.authenticate(password)){
            return res.status(401).json({
                message: 'Email and password do not match.'
            })
        }

        // generate token and send to client
        const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' })
        const { _id, name, email, role } = user

        return res.json({
            token,
            user: { _id, name, email, role },
            message: 'You have successfully logged in!',
        })
    })

}

exports.requireSignin = expressJwt({secret: process.env.JWT_SECRET, algorithms: ['HS256'] })

exports.authMiddleware = (req, res, next) => {
    const authUserId = req.user._id
    User.findOne({ _id: authUserId }).exec((err, user) => {
        if (err || !user) {
            return res.status(400).json({
                error: `User not found. ${err}`
            })
        }
        req.profile = user
        next()
    })
}

exports.adminMiddleware = (req, res, next) => {
    const adminUserId = req.user._id
    User.findOne({ _id: adminUserId }).exec((err, user) => {
        if (err || !user) {
            return res.status(400).json({
                error: `User not found. ${err}`
            })
        }

        if(user.role !== 'admin'){
            return res.status(400).json({
                error: 'Admin resource. Access denied'
            })
        }

        req.profile = user
        next()
    })
}

exports.forgotPassword = (req, res) => {
    const { email } = req.body

    User.findOne({ email }).exec((err, user) => {
        if (err || !user) {
            return res.status(400).json({
                error: 'User with that email does not exist',
            })
        }
    
        const token = jwt.sign({ name: user.name }, process.env.JWT_RESET_PASSWORD, { expiresIn: '10m' })
        const params = forgotPasswordEmailParams(email, token)
    
        return User.updateOne({ resetPasswordLink: token }, (err, success) => {
            if (err) {
                console.log(err)
                return res.status(400).json({
                    error: 'Password reset failed.'
                })
            }
            const sendEmail = ses.sendEmail(params).promise()
            sendEmail
            .then(data => {
                console.log('ses reset password successful', data)
                return res.json({
                    message: `Email has been sent to ${email}. Click on the link to reset your password.`
                })
            })
            .catch(error => {
                console.log('ses reset password failed', error)
                return res.json({
                    message: `We could not verify your email.`
                })
            })
        })
    })
}

exports.resetPassword = (req, res) => {
    const { resetPasswordLink, newPassword } = req.body

    if (resetPasswordLink) {
        jwt.verify(resetPasswordLink, process.env.JWT_RESET_PASSWORD, function(err, decoded) {

            if (err) {
                console.log(err)
                if (err.name === 'TokenExpiredError') {
                    return res.status(401).json({
                        error: 'Expired link. Try again.'
                    })
                }
                return res.status(500).json({
                    error: err,
                    log: 'log',
                })
            }
            
            User.findOne({ resetPasswordLink }).exec((err, user) => {
                if (err || !user) {
                    return res.status(400).json({
                        error: 'Invalid token. Try again.'
                    })
                }

                const updatedFields = {
                    password: newPassword,
                    resetPasswordLink: '',
                }

                user = _.extend(user, updatedFields)

                user.save((err, result) => {
                    if (err) {
                        return res.status(400).json({
                            error: 'Password reset failed. Try again',
                        })
                    }

                    return res.json({
                        message: 'Great! Now you can login with your new password',
                    })
                })
            })
    
        })
    } else {
        return res.json({
            message: `ay ay ay ${resetPasswordLink} ${newPassword}`,
        })
    }
}