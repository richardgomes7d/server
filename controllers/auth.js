const User = require('../models/user')
const AWS = require('aws-sdk')
const jwt = require('jsonwebtoken')
const shortId = require('shortid')
const { registerEmailParams } = require('../helpers/email')

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
                error: 'Please contact support. Honestly, I have no idea what happened.'
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
    console.table({ email, password })
}