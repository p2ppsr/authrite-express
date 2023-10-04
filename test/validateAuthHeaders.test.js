/* eslint-env jest */
const bsv = require('babbage-bsv')
const validateAuthHeaders = require('../src/utils/validateAuthHeaders')
const getResponseAuthHeaders = require('../src/utils/getResponseAuthHeaders')

const AUTHRITE_VERSION = '0.2'
const TEST_CLIENT_PRIVATE_KEY = '0d7889a0e56684ba795e9b1e28eb906df43454f8172ff3f6807b8cf9464994df'
const TEST_SERVER_PRIVATE_KEY = '6dcc124be5f382be631d49ba12f61adbce33a5ac14f6ddee12de25272f943f8b'
const CLIENT_NONCE = 'HtoBsUgDzj5orHDv1N2zdtiQpDM+aKwGY4VthxDYRHg='
const SERVER_NONCE = 'Ea2SOkMQiMbdCv4uinGmVIqAT+mRkq9VSIX+LG6cKso='

/**
 * Basic tests for the validateAuthHeaders helper function which is currently only used authrite server-side code
 */
describe('validateAuthHeaders', () => {
  afterEach(() => {
    jest.clearAllMocks()
  })
  it('successfully validates request auth headers', async () => {
    // TODO: This code is wrong, it needs to generate the client auth headers once we have access to test correctly!!!
    const authHeaders = await getResponseAuthHeaders({
      authrite: AUTHRITE_VERSION,
      serverPrivateKey: TEST_SERVER_PRIVATE_KEY,
      clientPublicKey: new bsv.PrivateKey(TEST_CLIENT_PRIVATE_KEY).publicKey.toString('hex'),
      clientNonce: CLIENT_NONCE,
      serverNonce: SERVER_NONCE,
      messageToSign: 'messageTest',
      certificates: [],
      requestedCertificates: []
    })

    const verified = await validateAuthHeaders({
      messageToSign: 'messageTest',
      authHeaders,
      serverPrivateKey: TEST_SERVER_PRIVATE_KEY
    })

    expect(verified).toEqual(true)
  })
})
