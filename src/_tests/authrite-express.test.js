/* eslint-env jest */
const bsv = require('bsv')
const crypto = require('crypto')
const sendover = require('sendover')

const { middleware } = require('../index')
const createNonce = require('../utils/createNonce')
const verifyNonce = require('../utils/verifyNonce')

const TEST_CLIENT_PRIVATE_KEY = '0d7889a0e56684ba795e9b1e28eb906df43454f8172ff3f6807b8cf9464994df'
const TEST_SERVER_PRIVATE_KEY = '6dcc124be5f382be631d49ba12f61adbce33a5ac14f6ddee12de25272f943f8b'

const mockRes = {
  status: jest.fn(() => mockRes),
  json: jest.fn(() => mockRes),
  unsignedJson: jest.fn(() => mockRes)
}
let mockReq
const mockNext = () => {}

describe('authrite', () => {
  beforeEach(() => {
    mockReq = {
      body: {
        authrite: '0.1',
        identityKey: bsv.PrivateKey.fromHex(TEST_SERVER_PRIVATE_KEY).publicKey.toString()
      },
      path: '/authrite/initialRequest'
    }
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
    const authriteMiddleware = middleware({
      serverPrivateKey: TEST_SERVER_PRIVATE_KEY,
      initalRequestPath: '/authrite/initialRequest'
    })

    authriteMiddleware(mockReq, mockRes)
    expect(mockRes.status).toHaveBeenLastCalledWith(200)
    expect(mockRes.json).toHaveBeenCalledWith({
      authrite: '0.1',
      messageType: 'initialResponse',
      identityKey: bsv.PrivateKey.fromHex(TEST_SERVER_PRIVATE_KEY).publicKey.toString(),
      nonce: expect.any(String),
      certificates: '[]',
      requestedCertificates: '[]',
      signature: expect.any(String)
    })
  })
  it('throws an error if the authrite versions do not match', async () => {
    // Mock a request with a different authrite version
    mockReq = {
      ...mockReq,
      body: {
        ...this.body,
        authrite: '0.2'
      }
    }
    const authriteMiddleware = middleware({
      serverPrivateKey: TEST_SERVER_PRIVATE_KEY,
      initalRequestPath: '/authrite/initialRequest'
    })
    authriteMiddleware(mockReq, mockRes)
    // Expect an error to be returned
    expect(mockRes.status).toHaveBeenLastCalledWith(400)
    expect(mockRes.json).toHaveBeenCalledWith({
      error: 'Authrite version incompatible'
    })
  })
  it('throws an error if the siganture is invalid', async () => {
    const serverNonce = createNonce(TEST_SERVER_PRIVATE_KEY)
    const clientNonce = createNonce(TEST_CLIENT_PRIVATE_KEY)

    const derivedClientPrivateKey = sendover.getPaymentPrivateKey({
      recipientPrivateKey: TEST_CLIENT_PRIVATE_KEY,
      senderPublicKey: bsv.PrivateKey.fromHex(TEST_SERVER_PRIVATE_KEY).publicKey.toString(),
      invoiceNumber: 'authrite message signature-' + clientNonce + ' ' + serverNonce + 'badData',
      returnType: 'hex'
    })
    const dataToSign = JSON.stringify(mockReq.body)
    const requestSignature = bsv.crypto.ECDSA.sign(
      bsv.crypto.Hash.sha256(Buffer.from(dataToSign)),
      bsv.PrivateKey.fromHex(derivedClientPrivateKey)
    )

    mockReq = {
      ...mockReq,
      headers: {
        'X-Authrite': '0.1',
        'X-Authrite-Identity-Key': bsv.PrivateKey.fromHex(TEST_CLIENT_PRIVATE_KEY).publicKey.toString(),
        'X-Authrite-Nonce': clientNonce,
        'X-Authrite-YourNonce': serverNonce,
        'X-Authrite-Certificates': [],
        'X-Authrite-Signature': requestSignature.toString()
      }
    }
    const authriteMiddleware = middleware({
      serverPrivateKey: TEST_SERVER_PRIVATE_KEY,
      initalRequestPath: '/apiRoute'
    })

    authriteMiddleware(mockReq, mockRes, mockNext)
    expect(mockRes.status).toHaveBeenLastCalledWith(401)
    expect(mockRes.unsignedJson).toHaveBeenCalledWith({
      error: 'Signature verification failed!'
    })
  })
  it('returns a valid response to a valid request from the client', async () => {
    const serverNonce = createNonce(TEST_SERVER_PRIVATE_KEY)
    const clientNonce = createNonce(TEST_CLIENT_PRIVATE_KEY)

    const derivedClientPrivateKey = sendover.getPaymentPrivateKey({
      recipientPrivateKey: TEST_CLIENT_PRIVATE_KEY,
      senderPublicKey: bsv.PrivateKey.fromHex(TEST_SERVER_PRIVATE_KEY).publicKey.toString(),
      invoiceNumber: 'authrite message signature-' + clientNonce + ' ' + serverNonce,
      returnType: 'hex'
    })
    const dataToSign = JSON.stringify(mockReq.body)
    const requestSignature = bsv.crypto.ECDSA.sign(
      bsv.crypto.Hash.sha256(Buffer.from(dataToSign)),
      bsv.PrivateKey.fromHex(derivedClientPrivateKey)
    )

    mockReq = {
      ...mockReq,
      headers: {
        'X-Authrite': '0.1',
        'X-Authrite-Identity-Key': bsv.PrivateKey.fromHex(TEST_CLIENT_PRIVATE_KEY).publicKey.toString(),
        'X-Authrite-Nonce': clientNonce,
        'X-Authrite-YourNonce': serverNonce,
        'X-Authrite-Certificates': [],
        'X-Authrite-Signature': requestSignature.toString()
      }
    }
    const authriteMiddleware = middleware({
      serverPrivateKey: TEST_SERVER_PRIVATE_KEY,
      initalRequestPath: '/apiRoute'
    })

    authriteMiddleware(mockReq, mockRes, mockNext)
    console.log(mockRes.unsignedJson)
    // expect(mockRes.unsignedJson).toHaveBeenCalledWith({
    //   somethingElse: 'data'
    // })
  })
  // it('throws an error if the server nonce cannot be verified', async () => {
  //   const serverNonce = createNonce(TEST_SERVER_PRIVATE_KEY)
  //   const clientNonce = createNonce(TEST_CLIENT_PRIVATE_KEY)

  //   const derivedClientPrivateKey = sendover.getPaymentPrivateKey({
  //     recipientPrivateKey: TEST_CLIENT_PRIVATE_KEY,
  //     senderPublicKey: bsv.PrivateKey.fromHex(TEST_SERVER_PRIVATE_KEY).publicKey.toString(),
  //     invoiceNumber: 'authrite message signature-' + clientNonce + ' ' + serverNonce,
  //     returnType: 'hex'
  //   })
  //   const dataToSign = JSON.stringify(mockReq.body)
  //   const requestSignature = bsv.crypto.ECDSA.sign(
  //     bsv.crypto.Hash.sha256(Buffer.from(dataToSign)),
  //     bsv.PrivateKey.fromHex(derivedClientPrivateKey)
  //   )

  //   mockReq = {
  //     ...mockReq,
  //     headers: {
  //       'X-Authrite': '0.1',
  //       'X-Authrite-Identity-Key': bsv.PrivateKey.fromHex(TEST_SERVER_PRIVATE_KEY).publicKey.toString(),
  //       'X-Authrite-Nonce': serverNonce + 'x',
  //       'X-Authrite-YourNonce': clientNonce,
  //       'X-Authrite-Certificates': [],
  //       'X-Authrite-Signature': requestSignature.toString()
  //     }
  //   }
  //   const authriteMiddleware = middleware({
  //     serverPrivateKey: TEST_SERVER_PRIVATE_KEY,
  //     initalRequestPath: '/apiRoute'
  //   })

  //   const response = authriteMiddleware(mockReq, mockRes)
  //   expect(response.status).toHaveBeenLastCalledWith(401)
  //   expect(mockRes.unsignedJson).toHaveBeenCalledWith({
  //     error: 'show sum\' R.E.S.P.E.C.T.'
  //   })
  // })
})
