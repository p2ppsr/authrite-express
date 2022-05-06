// Example express server that makes use of authrite middleware
const express = require('express')
const app = express()
const authrite = require('../../src/index')
const bodyParser = require('body-parser')
// const cors = require('cors')

const TEST_SERVER_PRIVATE_KEY = '6dcc124be5f382be631d49ba12f61adbce33a5ac14f6ddee12de25272f943f8b'

app.use(bodyParser.json())
// Add the Authrite middleware
app.use(authrite.middleware({
  serverPrivateKey: TEST_SERVER_PRIVATE_KEY,
  initalRequestPath: '/authrite/initialRequest'
}))

// app.post('/authrite/initialRequest', (req, res, next) => {
//   res.send({ message: 'Hello Authrite!' })
// })

app.post('/apiRoute', (req, res, next) => {
  res.json({ user: 'data' })

  //   res.setHeader('Access-Control-Allow-Origin', 'http://localhost:4000');
  //   res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, PATCH, DELETE');
  //   res.setHeader('Access-Control-Allow-Headers', 'X-Requested-With,content-type,x-authrite');
  //   res.setHeader('Access-Control-Allow-Credentials', true)
  next()
})
module.exports = app
