/* eslint-env jest */
// const bsv = require('bsv')
// const request = require('supertest')
const app = require('./server')
const { Authrite } = require('../../../authrite-js/src/authrite')

const TEST_CLIENT_PRIVATE_KEY = '0d7889a0e56684ba795e9b1e28eb906df43454f8172ff3f6807b8cf9464994df'
const TEST_SERVER_BASEURL = 'http://localhost:5000'

let server
describe('authrite', () => {
  beforeAll(() => {
    // Wait to start the server before running tests.
    return new Promise(resolve => {
      server = app.listen(5000, () => {
        resolve()
      })
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
