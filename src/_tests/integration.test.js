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
    console.log(Buffer.from(response.body).toString('utf8'))
  }, 100000)

  // TODO: Refactor to deal with no method specified, and
  // TODO: if it is a get request which should have no body.
  it('Creates an initial request with no method specified', async () => {
    const authrite = new Authrite({
      baseUrl: TEST_SERVER_BASEURL,
      clientPrivateKey: TEST_CLIENT_PRIVATE_KEY,
      initialRequestPath: '/authrite/initialRequest',
      initialRequestMethod: 'POST'
    })
    const response = await authrite.request('/getSomeData', {
      payload: {
        user: 'Bob',
        message: 'message from client'
      }
    })
    console.log(JSON.parse(Buffer.from(response.body).toString('utf8')).message)
  }, 100000)
})
