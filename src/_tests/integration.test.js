/* eslint-env jest */
const { Authrite } = require('authrite-js')
const fs = require('fs').promises

const TEST_CLIENT_PRIVATE_KEY = '0d7889a0e56684ba795e9b1e28eb906df43454f8172ff3f6807b8cf9464994df'
const TEST_SERVER_PRIVATE_KEY = '6dcc124be5f382be631d49ba12f61adbce33a5ac14f6ddee12de25272f943f8b'
let TEST_SERVER_BASEURL = 'http://localhost:'

// Example express server that makes use of authrite middleware
const express = require('express')
const app = express()
const authrite = require('../index')
// Set a data limit to allow larger payloads
app.use(express.json({ limit: '50mb' }))
app.use(express.urlencoded({ limit: '50mb' }))

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
          app.post('/apiRoute', (req, res) => {
            res.json({ user: 'data' })
          })
          app.get('/getData', (req, res) => {
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
      clientPrivateKey: TEST_CLIENT_PRIVATE_KEY,
      initialRequestPath: '/authrite/initialRequest'
    })
    const response = await authrite.request(TEST_SERVER_BASEURL + '/apiRoute')
    const responseData = JSON.parse(Buffer.from(response.body).toString('utf8'))
    expect(responseData).toEqual({ user: 'data' })
  }, 100000)

  it('Throws an error if the route does not exist on the server', async () => {
    const authrite = new Authrite({
      clientPrivateKey: TEST_CLIENT_PRIVATE_KEY,
      initialRequestPath: '/authrite/initialRequest'
    })
    await expect(authrite.request(TEST_SERVER_BASEURL + '/someRandomRoute', {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json'
      }
    })).rejects.toHaveProperty('message', 'The first argument must be of type string or an instance of Buffer, ArrayBuffer, or Array or an Array-like Object. Received null')
  }, 100000)

  it('Throws an error if an invalid request method is provided', async () => {
    const authrite = new Authrite({
      baseUrl: TEST_SERVER_BASEURL,
      clientPrivateKey: TEST_CLIENT_PRIVATE_KEY,
      initialRequestPath: '/authrite/initialRequest',
      initialRequestMethod: 'POST'
    })
    await expect(authrite.request('/someRandomRoute', {
      method: 'IS_THIS_A_REQUEST_METHOD?',
      headers: {
        'Content-Type': 'application/json'
      }
    })).rejects.toHaveProperty('message', 'FetchConfig not configured correctly! ErrorMessage: Method must be a valid HTTP token ["IS_THIS_A_REQUEST_METHOD?"]')
  }, 100000)

  it('Creates a GET request from the client to the server', async () => {
    const authrite = new Authrite({
      baseUrl: TEST_SERVER_BASEURL,
      clientPrivateKey: TEST_CLIENT_PRIVATE_KEY,
      initialRequestPath: '/authrite/initialRequest',
      initialRequestMethod: 'POST'
    })
    const response = await authrite.request('/getData', {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json'
      }
    })
    const responseData = JSON.parse(Buffer.from(response.body).toString('utf8'))
    expect(responseData).toEqual({ user: 'data' })
  }, 100000)

  it('Creates a request with a payload from the client to the server', async () => {
    const authrite = new Authrite({
      baseUrl: TEST_SERVER_BASEURL,
      clientPrivateKey: TEST_CLIENT_PRIVATE_KEY
    })
    const body = {
      user: 'Bob',
      message: 'message from client'
    }
    const response = await authrite.request('/sendSomeData', {
      body: JSON.stringify(body),
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      }
    })
    const responseData = JSON.parse(Buffer.from(response.body).toString('utf8'))
    expect(responseData.clientData).toEqual(body)
  }, 100000)

  it('Creates a request with a payload containing a buffer from the client to the server', async () => {
    const authrite = new Authrite({
      baseUrl: TEST_SERVER_BASEURL,
      clientPrivateKey: TEST_CLIENT_PRIVATE_KEY
    })
    const dataBuffer = Buffer.from('Hello, Authrite', 'utf8')
    const body = {
      user: 'Bob',
      buffer: dataBuffer
    }
    const response = await authrite.request('/sendSomeData', {
      body,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      }
    })
    const responseData = JSON.parse(Buffer.from(response.body).toString('utf8'))
    const data = Buffer.from(responseData.clientData.buffer).toString('utf8')
    expect(data).toEqual('Hello, Authrite')
  }, 100000)

  it('Creates a request with a payload containing an image buffer from the client to the server', async () => {
    const authrite = new Authrite({
      baseUrl: TEST_SERVER_BASEURL,
      clientPrivateKey: TEST_CLIENT_PRIVATE_KEY
    })
    // Get image buffer from local test file
    const filePath = './src/_tests/images/'
    const dataBuffer = Buffer.from(await fs.readFile(filePath + 'inputTestImage.png'), 'utf-8')
    const body = {
      user: 'Bob',
      buffer: dataBuffer
    }
    // Send the image data to the server, and then get the same data back from the server
    const response = await authrite.request('/sendSomeData', {
      body,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      }
    })
    const responseData = JSON.parse(Buffer.from(response.body).toString('utf8'))
    const fileContents = Buffer.from(responseData.clientData.buffer.data, 'base64')
    // Write the image data to a file
    await fs.writeFile(filePath + 'outputTestImage.png', fileContents, 'base64', (e) => {
      console.log(e)
    })
    // Check if the file exists
    let exists = false
    try {
      if (fs.access(filePath + 'outputTestImage.png')) {
        exists = true
      }
    } catch (err) {
      console.error(err)
    }
    expect(exists).toEqual(true)
  }, 100000)

  it('Creates a request with a payload to the server with no method specified', async () => {
    const authrite = new Authrite({
      baseUrl: TEST_SERVER_BASEURL,
      clientPrivateKey: TEST_CLIENT_PRIVATE_KEY,
      initialRequestMethod: 'POST'
    })
    const body = {
      user: 'Bob',
      message: 'message from client'
    }
    const response = await authrite.request('/sendSomeData', {
      body: JSON.stringify(body),
      headers: {
        'Content-Type': 'application/json'
      }
    })
    const responseData = JSON.parse(Buffer.from(response.body).toString('utf8'))
    expect(responseData.clientData).toEqual(body)
  }, 100000)

  it('Creates a request with a payload to the server with no method or header specified', async () => {
    const authrite = new Authrite({
      baseUrl: TEST_SERVER_BASEURL,
      clientPrivateKey: TEST_CLIENT_PRIVATE_KEY
    })
    const body = {
      user: 'Bob',
      message: 'message from client'
    }
    const response = await authrite.request('/sendSomeData', {
      body: JSON.stringify(body)
    })
    const responseData = JSON.parse(Buffer.from(response.body).toString('utf8'))
    expect(responseData.clientData).toEqual(body)
  }, 100000)

  it('Creates a request with a payload that is not a string', async () => {
    const authrite = new Authrite({
      baseUrl: TEST_SERVER_BASEURL,
      clientPrivateKey: TEST_CLIENT_PRIVATE_KEY,
      initialRequestMethod: 'POST'
    })
    // An example song object that can be used in a request body
    class Song {
      constructor (title, length, artist) {
        this.title = title
        this.length = length
        this.artist = artist
      }
    }
    const body = {
      songs: [
        new Song('song1', '3:30', 'Brayden Langley'),
        new Song('song2', '3:30', 'Brayden Langley'),
        new Song('song3', '3:30', 'Brayden Langley'),
        new Song('song4', '3:30', 'Brayden Langley'),
        new Song('song5', '3:30', 'Brayden Langley'),
        new Song('song6', '3:30', 'Brayden Langley'),
        new Song('song7', '3:30', 'Brayden Langley')
      ]
    }
    const response = await authrite.request('/sendSomeData', {
      body,
      method: 'POST'
    })
    const responseData = JSON.parse(Buffer.from(response.body).toString('utf8'))
    expect(responseData.clientData).toEqual(body)
  }, 100000)

  it('Does not throw an error if the body of a POST request is empty', async () => {
    const authrite = new Authrite({
      baseUrl: TEST_SERVER_BASEURL,
      clientPrivateKey: TEST_CLIENT_PRIVATE_KEY
    })
    const response = await authrite.request('/sendSomeData', {
      body: undefined,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      }
    })
    const responseData = JSON.parse(Buffer.from(response.body).toString('utf8'))
    expect(responseData.clientData).toEqual({})
  }, 100000)

  it('throws an error if the fetchConfig contains a body for a GET request', async () => {
    const authrite = new Authrite({
      baseUrl: TEST_SERVER_BASEURL,
      clientPrivateKey: TEST_CLIENT_PRIVATE_KEY
    })
    await expect(authrite.request('/sendSomeData', {
      body: JSON.stringify({ data: 'should not have a body' }),
      method: 'GET',
      headers: {
        'Content-Type': 'application/json'
      }
    })).rejects.toHaveProperty('message', 'FetchConfig not configured correctly! ErrorMessage: Request with GET/HEAD method cannot have body')
  }, 100000)
})
