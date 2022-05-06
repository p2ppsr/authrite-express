/* eslint-env jest */
const bsv = require('bsv')
const crypto = require('crypto')
const sendover = require('sendover')

const { middleware } = require('../index')
const createNonce = require('../utils/createNonce')
const verifyNonce = require('../utils/verifyNonce')

const TEST_CLIENT_PRIVATE_KEY = '0d7889a0e56684ba795e9b1e28eb906df43454f8172ff3f6807b8cf9464994df'
const TEST_SERVER_PRIVATE_KEY = '6dcc124be5f382be631d49ba12f61adbce33a5ac14f6ddee12de25272f943f8b'

const TEST_SERVER_NONCE = createNonce(TEST_SERVER_PRIVATE_KEY)
const TEST_CLIENT_NONCE = crypto.randomBytes(32).toString('base64')
const TEST_REQ_DATA = { hello: 'Authrite' }

// Create a valid client signature for testing
const derivedClientPrivateKey = sendover.getPaymentPrivateKey({
  recipientPrivateKey: TEST_CLIENT_PRIVATE_KEY,
  senderPublicKey: bsv.PrivateKey.fromHex(TEST_SERVER_PRIVATE_KEY).publicKey.toString(),
  invoiceNumber: 'authrite message signature-' + TEST_CLIENT_NONCE + ' ' + TEST_SERVER_NONCE,
  returnType: 'hex'
})

const dataToSign = JSON.stringify(TEST_REQ_DATA)
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
          identityKey: bsv.PrivateKey.fromString(TEST_CLIENT_PRIVATE_KEY)
            .publicKey.toString(),
          nonce: TEST_CLIENT_NONCE,
          requestedCertificates: []
        },
        path: '/authrite/initialRequest'
      },
      normalRequest: {
        body: TEST_REQ_DATA,
        path: '/apiRoute',
        headers: {
          'X-Authrite': '0.1',
          'X-Authrite-Identity-Key': bsv.PrivateKey.fromHex(TEST_CLIENT_PRIVATE_KEY).publicKey.toString(),
          'X-Authrite-Nonce': TEST_CLIENT_NONCE,
          'X-Authrite-YourNonce': TEST_SERVER_NONCE,
          'X-Authrite-Certificates': [],
          'X-Authrite-Signature': requestSignature.toString()
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
    mockReq = VALID.initialRequest
    const authriteMiddleware = middleware({
      serverPrivateKey: TEST_SERVER_PRIVATE_KEY
    })
    authriteMiddleware(mockReq, mockRes, mockNext)
    expect(mockRes.status).toHaveBeenLastCalledWith(200)
    expect(mockRes.json).toHaveBeenCalledWith({
      authrite: '0.1',
      messageType: 'initialResponse',
      identityKey: bsv.PrivateKey.fromHex(TEST_SERVER_PRIVATE_KEY).publicKey.toString(),
      nonce: expect.any(String),
      certificates: [],
      requestedCertificates: [],
      signature: expect.any(String)
    })

    // TODO: 
    // The client derives the server's signing key
    // const serverSigningKey = sendover.getP
    console.log(mockRes.json)
    debugger
    const signingPublicKey = sendover.getPaymentAddress({
      senderPrivateKey: TEST_CLIENT_PRIVATE_KEY,
      recipientPublicKey: mockRes.json.identityKey,
      invoiceNumber: 'authrite message signature-' + TEST_CLIENT_NONCE + ' ' + mockRes.nonce,
      returnType: 'publicKey'
    })
    // verifies the signature.
    const message = TEST_CLIENT_NONCE + mockRes.nonce
    const verified = bsv.crypto.ECDSA.verify(
      bsv.crypto.Hash.sha256(Buffer.from(message)),
      mockRes.siganture,
      bsv.PublicKey.fromString(signingPublicKey)
    )
    expect(verified).toBeTrue()
  })
  it('throws an error if the authrite versions do not match in the initial request', async () => {
    // Mock an initial request with a different authrite version
    mockReq = VALID.initialRequest
    mockReq.body.authrite = '0.2'
    const authriteMiddleware = middleware({
      serverPrivateKey: TEST_SERVER_PRIVATE_KEY
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
    mockReq.headers['X-Authrite'] = '0.2'
    const authriteMiddleware = middleware({
      serverPrivateKey: TEST_SERVER_PRIVATE_KEY
    })
    authriteMiddleware(mockReq, mockRes)
    // Expect an error to be returned
    expect(mockRes.status).toHaveBeenLastCalledWith(400)
    expect(mockRes.json).toHaveBeenCalledWith({
      error: 'Authrite version incompatible'
    })
  })
  it('throws an error if the siganture is invalid', async () => {
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
    mockReq.headers['X-Authrite-Signature'] = badSig.toString()
    const authriteMiddleware = middleware({
      serverPrivateKey: TEST_SERVER_PRIVATE_KEY
    })
    authriteMiddleware(mockReq, mockRes, mockNext)
    expect(mockRes.status).toHaveBeenLastCalledWith(401)
    expect(mockRes.json).toHaveBeenCalledWith({
      error: 'Signature verification failed!'
    })
  })
  it('returns a valid response to a valid request from the client', async () => {
    mockReq = VALID.normalRequest
    const authriteMiddleware = middleware({
      serverPrivateKey: TEST_SERVER_PRIVATE_KEY
    })

    authriteMiddleware(mockReq, mockRes, mockNext)

    const data = { test: 'response' }
    mockRes.json(data)
    expect(mockRes.json).toHaveBeenCalledWith(data)

    // Verify the response signature from the server.

    expect(mockRes.headers['X-Authrite-Signature']).toBeTruthy()
    expect(mockReq.authrite.identityKey).toBeTruthy()
    const signingPublicKey = sendover.getPaymentAddress({
      senderPrivateKey: TEST_SERVER_PRIVATE_KEY,
      recipientPublicKey: bsv.PrivateKey.fromHex(TEST_CLIENT_PRIVATE_KEY).publicKey.toString(),
      invoiceNumber: 'authrite message signature-' + mockRes.headers['X-Authrite-Nonce'] + ' ' + mockRes.headers['X-Authrite-YourNonce'],
      returnType: 'publicKey'
    })
    const signature = bsv.crypto.ECDSA.sign(
      bsv.crypto.Hash.sha256(Buffer.from(data)),
      bsv.PrivateKey.fromHex(derivedPrivateKey)
    )
    const verified = bsv.crypto.ECDSA.verify(
    bsv.crypto.Hash.sha256(Buffer.from(messageToVerify)),
    signature,
    bsv.PublicKey.fromString(signingPublicKey)
  )
    expect(verified).toBeTrue()
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
