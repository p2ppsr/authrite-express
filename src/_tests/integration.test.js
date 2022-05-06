/* eslint-env jest */
// const bsv = require('bsv')
// const request = require('supertest')
const app = require('./server')
const { Authrite } = require('../../../authrite-js/src/authrite')

const TEST_CLIENT_PRIVATE_KEY = '0d7889a0e56684ba795e9b1e28eb906df43454f8172ff3f6807b8cf9464994df'

describe('authrite', () => {
  beforeEach(() => {
  })
  afterEach(() => {
    jest.clearAllMocks()
  })
  it('Starts an express server', async () => {
    app.listen(5000, () => {
      console.log('server started')
    })
  })
  // Example test using require('supertest')
  //   it('Creates an initial request from the client to the server', async () => {
  //     const res = await request(app).post('/authrite/initialRequest')
  //       .send({
  //         authrite: '0.1',
  //         identityKey: bsv.PrivateKey.fromString(TEST_CLIENT_PRIVATE_KEY).publicKey.toString(),
  //         requestedCertificates: []
  //       }).expect(200)
  //     console.log(res.text)
  //   })
  it('Creates an initial request from the client to the server', async () => {
    const authrite = new Authrite({
      serverUrl: 'http://localhost:5000',
      clientPrivateKey: TEST_CLIENT_PRIVATE_KEY,
      initialRequestPath: '/authrite/initialRequest',
      initialRequestMethod: 'POST'
    })
    const response = await authrite.request('/apiRoute')
  })
})
