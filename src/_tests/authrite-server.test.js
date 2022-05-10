/* eslint-env jest */
const bsv = require('bsv')
const crypto = require('crypto')
const sendover = require('sendover')

const { middleware } = require('../index')
const createNonce = require('../utils/createNonce')
const verifyNonce = require('../utils/verifyNonce')

const TEST_CLIENT_PRIVATE_KEY = '0d7889a0e56684ba795e9b1e28eb906df43454f8172ff3f6807b8cf9464994df'
const TEST_SERVER_PRIVATE_KEY = '6dcc124be5f382be631d49ba12f61adbce33a5ac14f6ddee12de25272f943f8b'
const TEST_SERVER_BASEURL = 'http://localhost:5000'

const TEST_SERVER_NONCE = createNonce(TEST_SERVER_PRIVATE_KEY)
const TEST_CLIENT_NONCE = crypto.randomBytes(32).toString('base64')
const TEST_REQ_DATA = {
  body: {
    user: 'Bob',
    message: 'message from client'
  },
  method: 'POST'
}

// Create a valid client signature for testing
// const requestNonce = crypto.randomBytes(32).toString('base64')
const derivedClientPrivateKey = sendover.getPaymentPrivateKey({
  recipientPrivateKey: TEST_CLIENT_PRIVATE_KEY,
  senderPublicKey: bsv.PrivateKey.fromHex(TEST_SERVER_PRIVATE_KEY).publicKey.toString(),
  invoiceNumber: 'authrite message signature-' + TEST_CLIENT_NONCE + ' ' + TEST_SERVER_NONCE,
  returnType: 'hex'
})

const dataToSign = JSON.stringify(TEST_REQ_DATA.body)
const requestSignature = bsv.crypto.ECDSA.sign(
  bsv.crypto.Hash.sha256(Buffer.from(dataToSign)),
  bsv.PrivateKey.fromHex(derivedClientPrivateKey)
)

const mockRes = {
  status: jest.fn(() => mockRes),
  json: jest.fn(() => mockRes),
  set: jest.fn(x => {
    mockRes.headers = x
    return mockRes
  }),
  headers: {}
}
let mockReq, VALID
const mockNext = () => {}

describe('authrite', () => {
  beforeEach(() => {
    VALID = {
      initialRequest: {
        body: {
          authrite: '0.1',
          identityKey: bsv.PrivateKey.fromHex(TEST_CLIENT_PRIVATE_KEY).publicKey.toString(),
          nonce: TEST_CLIENT_NONCE,
          requestedCertificates: []
        },
        path: '/authrite/initialRequest'
      },
      normalRequest: {
        body: TEST_REQ_DATA.body,
        method: TEST_REQ_DATA.method,
        path: '/apiRoute',
        headers: {
          'Content-Type': 'application/json',
          'x-authrite': '0.1',
          'x-authrite-identity-key': bsv.PrivateKey.fromHex(TEST_CLIENT_PRIVATE_KEY).publicKey.toString(),
          'x-authrite-nonce': TEST_CLIENT_NONCE,
          'x-authrite-yournonce': TEST_SERVER_NONCE,
          'x-authrite-certificates': [],
          'x-authrite-signature': requestSignature.toString()
        }
      }
    }
  })
  afterEach(() => {
    jest.clearAllMocks()
  })
  it('creates a verifiable 256-bit nonce', async () => {
    const nonce = createNonce(TEST_SERVER_PRIVATE_KEY)
    expect(Buffer.from(nonce, 'base64').byteLength).toEqual(32)
    expect(verifyNonce(nonce, TEST_SERVER_PRIVATE_KEY)).toEqual(true)
  })
  it('recognizes a false 256-bit nonce', async () => {
    const falseNonce = crypto.randomBytes(32).toString('base64')
    expect(verifyNonce(falseNonce, TEST_SERVER_PRIVATE_KEY)).toEqual(false)
  })
  it('responds properly to an initial request', async () => {
    mockReq = VALID.initialRequest // normal request
    const authriteMiddleware = middleware({
      serverPrivateKey: TEST_SERVER_PRIVATE_KEY,
      baseUrl: TEST_SERVER_BASEURL
    })
    const response = authriteMiddleware(mockReq, mockRes, mockNext)

    expect(response.status).toHaveBeenLastCalledWith(200)
    expect(mockRes.json).toHaveBeenCalledWith({
      authrite: '0.1',
      messageType: 'initialResponse',
      identityKey: bsv.PrivateKey.fromHex(TEST_SERVER_PRIVATE_KEY).publicKey.toString(),
      nonce: expect.any(String),
      certificates: [],
      requestedCertificates: [],
      signature: expect.any(String)
    })
  })
  it('throws an error if the authrite versions do not match in the initial request', async () => {
    // Mock an initial request with a different authrite version
    mockReq = VALID.initialRequest
    mockReq.body.authrite = '0.2'
    const authriteMiddleware = middleware({
      serverPrivateKey: TEST_SERVER_PRIVATE_KEY,
      baseUrl: TEST_SERVER_BASEURL
    })
    authriteMiddleware(mockReq, mockRes)
    // Expect an error to be returned
    expect(mockRes.status).toHaveBeenLastCalledWith(400)
    expect(mockRes.json).toHaveBeenCalledWith({
      error: 'Authrite version incompatible'
    })
  })
  it('throws an error if the authrite versions do not match in subsequent requests', async () => {
    mockReq = VALID.normalRequest
    // Mock an initial request with a different authrite version
    mockReq.headers['x-authrite'] = '0.2'
    const authriteMiddleware = middleware({
      serverPrivateKey: TEST_SERVER_PRIVATE_KEY,
      baseUrl: TEST_SERVER_BASEURL
    })
    authriteMiddleware(mockReq, mockRes)
    // Expect an error to be returned
    expect(mockRes.status).toHaveBeenLastCalledWith(400)
    expect(mockRes.json).toHaveBeenCalledWith({
      error: 'Authrite version incompatible'
    })
  })
  it('throws an error if the signature is invalid', async () => {
    mockReq = VALID.normalRequest
    const badKey = sendover.getPaymentPrivateKey({
      recipientPrivateKey: TEST_CLIENT_PRIVATE_KEY,
      senderPublicKey: bsv.PrivateKey.fromHex(TEST_SERVER_PRIVATE_KEY).publicKey.toString(),
      invoiceNumber: 'authrite message signature-' + TEST_CLIENT_NONCE + ' ' + TEST_SERVER_NONCE + 'badData',
      returnType: 'hex'
    })
    const dataToSign = JSON.stringify(mockReq.body)
    const badSig = bsv.crypto.ECDSA.sign(
      bsv.crypto.Hash.sha256(Buffer.from(dataToSign)),
      bsv.PrivateKey.fromHex(badKey)
    )
    mockReq.headers['x-authrite-signature'] = badSig.toString()
    const authriteMiddleware = middleware({
      serverPrivateKey: TEST_SERVER_PRIVATE_KEY,
      baseUrl: TEST_SERVER_BASEURL
    })
    authriteMiddleware(mockReq, mockRes, mockNext)
    expect(mockRes.status).toHaveBeenLastCalledWith(401)
    expect(mockRes.json).toHaveBeenCalledWith({
      error: 'Signature verification failed!'
    })
  })
  // Note: Request and response validated in integration test.
  it('returns a valid response to a valid request from the client', () => {
    mockReq = VALID.normalRequest
    const authriteMiddleware = middleware({
      serverPrivateKey: TEST_SERVER_PRIVATE_KEY,
      baseUrl: TEST_SERVER_BASEURL
    })
    authriteMiddleware(mockReq, mockRes, mockNext)
    const SERVER_MSG = { server: 'response' }
    mockRes.json(SERVER_MSG)
    const messageToVerify = JSON.stringify(SERVER_MSG)
    const invoiceNumber = `authrite message signature-${mockRes.headers['X-Authrite-YourNonce']} ${mockRes.headers['X-Authrite-Nonce']}`
    expect(bsv.crypto.ECDSA.verify(
      bsv.crypto.Hash.sha256(Buffer.from(messageToVerify)),
      bsv.crypto.Signature.fromString(mockRes.headers['X-Authrite-Signature']),
      bsv.PublicKey.fromString(sendover.getPaymentAddress({
        senderPrivateKey: TEST_CLIENT_PRIVATE_KEY,
        recipientPublicKey: bsv.PrivateKey.fromString(TEST_SERVER_PRIVATE_KEY).publicKey.toString(),
        invoiceNumber,
        returnType: 'publicKey'
      }))
    )).toEqual(true)
  })
})