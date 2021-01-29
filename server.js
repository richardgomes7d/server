const express = require('express')
const morgan = require('morgan')
const cors = require('cors')
const mongoose = require('mongoose')
const bodyParser = require('body-parser')
require('dotenv').config()

const app = express()

// db
mongoose
    .connect(process.env.DATABASE_CLOUD, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('DB connected'))
    .catch(err => console.log(err));

app.get('/', (req, res) => {
    res.json({
        data: 'pum pirín pum pai'
    })
})

// import routes
const authRoutes = require('./routes/auth')

// app middlewares
app.use(morgan('dev'))
app.use(bodyParser.json())
app.use(cors({ origin: process.env.CLIENT_URL }))

app.use('/api', authRoutes)

const port = process.env.PORT || 8000
app.listen(port, () => console.log(`API is running on port ${port}`))
