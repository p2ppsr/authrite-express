/* eslint-env jest */
const { Authrite } = require('../../../authrite-js/src/authrite') // !!!

const TEST_CLIENT_PRIVATE_KEY = '0d7889a0e56684ba795e9b1e28eb906df43454f8172ff3f6807b8cf9464994df'
const TEST_SERVER_PRIVATE_KEY = '6dcc124be5f382be631d49ba12f61adbce33a5ac14f6ddee12de25272f943f8b'
let TEST_SERVER_BASEURL = 'http://localhost:'

// Example express server that makes use of authrite middleware
const express = require('express')
const app = express()
const authrite = require('../index')
app.use(express.json())

let server
describe('authrite', () => {
  beforeAll(async () => {
    // Wait to start the server before running tests.
    TEST_SERVER_BASEURL += await new Promise((resolve, reject) => {
      try {
        server = app.listen(0, () => {
          // Add the Authrite middleware
  app.use(authrite.middleware({
    serverPrivateKey: TEST_SERVER_PRIVATE_KEY,
    baseUrl: `http://localhost:${server.address().port}`
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

          resolve(server.address().port)
        })
      } catch (e) {
        reject(e)
      }
    })
  })
  afterAll(() => {
    server.close()
  })
  beforeEach(() => {
  })
  afterEach(() => {
    jest.clearAllMocks()
  })

  // Note: clientPrivateKey and baseUrl requirements tested in authrite.test.js
  it('Creates an initial request from the client to the server', async () => {
    const authrite = new Authrite({
      baseUrl: TEST_SERVER_BASEURL,
      clientPrivateKey: TEST_CLIENT_PRIVATE_KEY,
      initialRequestPath: '/authrite/initialRequest',
      initialRequestMethod: 'POST'
    })
    const response = await authrite.request('/apiRoute')
    const responseData = JSON.parse(Buffer.from(response.body).toString('utf8'))
    expect(responseData).toEqual({ user: 'data' })
  }, 100000)

  it('Creates a request with a payload from the client to the server', async () => {
    const authrite = new Authrite({
      baseUrl: TEST_SERVER_BASEURL,
      clientPrivateKey: TEST_CLIENT_PRIVATE_KEY,
      initialRequestPath: '/authrite/initialRequest',
      initialRequestMethod: 'POST'
    })
    const payload = {
      user: 'Bob',
      message: 'message from client'
    }
    const response = await authrite.request('/sendSomeData', {
      payload,
      method: 'POST'
    })
    const responseData = JSON.parse(Buffer.from(response.body).toString('utf8'))
    expect(responseData.clientData).toEqual(payload)
  }, 100000)

  it('Creates a request with a payload to the server with no method specified', async () => {
    const authrite = new Authrite({
      baseUrl: TEST_SERVER_BASEURL,
      clientPrivateKey: TEST_CLIENT_PRIVATE_KEY,
      initialRequestPath: '/authrite/initialRequest',
      initialRequestMethod: 'POST'
    })
    const payload = {
      user: 'Bob',
      message: 'message from client'
    }
    const response = await authrite.request('/sendSomeData', {
      payload
    })
    const responseData = JSON.parse(Buffer.from(response.body).toString('utf8'))
    expect(responseData.clientData).toEqual(payload)
  }, 100000)

  it('Creates a request with a different payload', async () => {
    const authrite = new Authrite({
      baseUrl: TEST_SERVER_BASEURL,
      clientPrivateKey: TEST_CLIENT_PRIVATE_KEY,
      initialRequestPath: '/authrite/initialRequest',
      initialRequestMethod: 'POST'
    })
    const payload = {
      songs: JSON.stringify(['song1', 'song2', 'song3']),
      artist: 'Brayden Langley'
    }
    const response = await authrite.request('/sendSomeData', {
      payload,
      method: 'POST'
    })
    const responseData = JSON.parse(Buffer.from(response.body).toString('utf8'))
    expect(responseData.clientData).toEqual(payload)
  }, 100000)
})
