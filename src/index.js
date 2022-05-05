const bsv = require('bsv')
const crypto = require('crypto')
const { getPaymentAddress, getPaymentPrivateKey } = require('sendover')

const middleware = config => (req, res, next) =>
{
    // Generate a new server nonce to use for signing the response
    const serverNonce = crypto.randomBytes(32).toString('base64')

    // Temporarily save client request info for testing purposes
    clientIdentityKey = fetchConfig.headers['X-Authrite-Identity-Key']
    clientNonce = fetchConfig.headers['X-Authrite-Nonce']
    clientSig = fetchConfig.headers['X-Authrite-Signature']
    responseMessage = {
    message: 'hello Authrite'
    }
    const derivedPrivateKey = sendover.getPaymentPrivateKey({
    recipientPrivateKey: TEST_SERVER_PRIVATE_KEY,
    senderPublicKey: fetchConfig.headers['X-Authrite-Identity-Key'],
    invoiceNumber: 'authrite message signature-' + fetchConfig.headers['X-Authrite-Nonce'] + ' ' + serverNonce,
    returnType: 'hex'
    })
    const responseSignature = bsv.crypto.ECDSA.sign(
    bsv.crypto.Hash.sha256(Buffer.from(JSON.stringify(responseMessage))),
    bsv.PrivateKey.fromHex(derivedPrivateKey))
}

module.exports = { middleware }