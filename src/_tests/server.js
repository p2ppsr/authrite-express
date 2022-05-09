// Example express server that makes use of authrite middleware
const express = require('express')
const app = express()
const authrite = require('../../src/index')

const TEST_SERVER_PRIVATE_KEY = '6dcc124be5f382be631d49ba12f61adbce33a5ac14f6ddee12de25272f943f8b'
const TEST_SERVER_BASEURL = 'http://localhost:5000'
app.use(express.json())
// Add the Authrite middleware
app.use(authrite.middleware({
  serverPrivateKey: TEST_SERVER_PRIVATE_KEY,
  baseUrl: TEST_SERVER_BASEURL
}))

// Example Routes
app.get('/apiRoute', (req, res) => {
  res.json({ user: 'data' })
})
app.post('/sendSomeData', (req, res) => {
  res.json({
    message: 'Hello, this is the server. Here is the data you sent:',
    clientData: req.body
  })
})
module.exports = app
