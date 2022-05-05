/* eslint-env jest */
const bsv = require('bsv')
const crypto = require('crypto')
const sendover = require('sendover')

const { middleware } = require('../index')
const createNonce = require('../utils/createNonce')
const verifyNonce = require('../utils/verifyNonce')

const mockRes = {
  status: jest.fn(() => mockRes),
  json: jest.fn(() => mockRes)
}

const mockReq = {
  body: { message: 'Hello' }
}

const TEST_CLIENT_PRIVATE_KEY = '0d7889a0e56684ba795e9b1e28eb906df43454f8172ff3f6807b8cf9464994df'
const TEST_SERVER_PRIVATE_KEY = '6dcc124be5f382be631d49ba12f61adbce33a5ac14f6ddee12de25272f943f8b'

describe('authrite', () => {
  beforeEach(() => {
  })
  afterEach(() => {
    jest.clearAllMocks()
  })
  it('creates a verifiable 32 byte nonce :)', async () => {
    const nonce = createNonce(TEST_SERVER_PRIVATE_KEY)
    expect(verifyNonce(nonce, TEST_SERVER_PRIVATE_KEY)).toEqual(true)
  })
  it('recognizes a false 32 byte nonce :(', async () => {
    const falseNonce = crypto.randomBytes(32).toString('base64')
    expect(verifyNonce(falseNonce, TEST_SERVER_PRIVATE_KEY)).toEqual(false)
  })
  it('responds properly to an initial request', async () => {
    const middlewareFunction = middleware({
      serverPrivateKey: TEST_SERVER_PRIVATE_KEY
    })

    middlewareFunction(req, mockRes)
  })
})
