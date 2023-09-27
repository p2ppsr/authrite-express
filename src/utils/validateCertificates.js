const authriteUtils = require('authrite-utils')

/**
 * Validates an array of certificates provided in a request
 * @param {object} obj - all params given in an object
 * @param {string} obj.serverPrivateKey - the server's private key to use in the field decryption process
 * @param {identityKey} obj.identityKey - of the client initiating the request
 * @param {Array} obj.certificates - provided to the server by the client
 * @returns {Array | object} - array of the validated certificates, or an Error object to return to the client
 */
const validateCertificates = async ({
  serverPrivateKey,
  identityKey,
  certificates
}) => {
  for (const c in certificates) {
    const cert = certificates[c]

    // Make sure the certificate subject is the same as the client
    if (cert.subject !== identityKey) {
      return {
        status: 'error',
        code: 'ERR_INVALID_SUBJECT',
        description: `The subject of one of your certificates ("${cert.subject}") is not the same as the request sender ("${identityKey}").`,
        identityKey,
        certificateSubject: cert.subject
      }
    }

    // Make sure the certificate signature is valid
    try {
      authriteUtils.verifyCertificateSignature(cert)
    } catch (err) {
      if (err.code && err.code.startsWith('ERR_AUTHRITE')) {
        return {
          status: 'error',
          code: err.code,
          description: err.message
        }
      } else {
        throw err
      }
    }

    // Check encrypted fields can be decrypted
    let decryptedFields = {}
    try {
      decryptedFields = await authriteUtils.decryptCertificateFields(
        cert,
        cert.keyring,
        serverPrivateKey
      )
    } catch (err) {
      return {
        status: 'error',
        code: 'ERR_DECRYPTION_FAILED',
        description: 'Could not decrypt certificate fields'
      }
    }

    certificates[c] = {
      ...cert,
      decryptedFields
    }
  }
  return certificates
}
module.exports = validateCertificates
