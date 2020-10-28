const AWS = require('aws-sdk');

const handle = require('lib/handle-await-error');

const AWS_REGION = 'eu-west-2';
const KEY_ID = 'arn:aws:kms:eu-west-2:587141933180:key/a903b7bf-81cf-4473-b938-e2bf807d9e47';
const PLAINTEXT_SECRET = 'this is very, very secret!';

/**
 * Returns an encrypted cyphertext, encoded in base64.
 */
const encrypt = async (kmsClient, keyId, plaintext) => {
  ({ CiphertextBlob: encryptedSecretBlob } = await kmsClient.encrypt({
    KeyId: keyId,
    Plaintext: plaintext,
  }).promise());

  return encryptedSecretBlob.toString('base64');
}

/**
 * Decrypts a cyphertext encoded in base64.
 */
const decrypt = async (kmsClient, keyId, base64EncodedCiphertext) => {
  const ciphertextBlob = Buffer.from(base64EncodedCiphertext, 'base64');
  const { Plaintext: plaintext } = await kmsClient.decrypt({
    KeyId: keyId,
    CiphertextBlob: ciphertextBlob,
  }).promise();
  return plaintext.toString('utf8');
}

exports.lambdaHandler = async () => {
  const kmsClient = new AWS.KMS({
    region: AWS_REGION,
  });

  // Encrypt
  const [
    err1,
    base64EncodedCiphertext,
  ] = await handle(encrypt(kmsClient, KEY_ID, PLAINTEXT_SECRET));
  if (err1) {
    return {
      statusCode: 500,
      body: 'Encryption failed!',
    }
  }

  // Decryption
  const decryptionSuccess = true;
  const [
    err2,
    plaintext,
  ] = await handle(decrypt(kmsClient, KEY_ID, base64EncodedCiphertext));
  if (err2) {
    decryptionSuccess = false;
  }

  return {
    statusCode: 200,
    body: JSON.stringify({
      base64EncodedCiphertext,
      decryptionSuccess,
      plainText: decryptionSuccess ? plaintext : undefined,
    }),
  }
};
