import {
  getKeyfromCertificateBuffer,
  getKeyFromAssertionBuffer
} from './uafcrypto'

function getRegistrationRequestTemplate() {
  return {
    uafRequest: [{
      header: {
        upv: {
          major: 1,
          minor: 1
        },
        op: 'Reg'
      }
    }]
  };
}

function getDeregistrationRequestTemplate() {
  return {
    uafRequest: [{
      header: {
        upv: {
          major: 1,
          minor: 1
        },
        op: 'Dereg'
      }
    }]
  };
}

function getAttestationPubKey(assertion) { // TODO: error handling

  if (assertion.TAG_UAFV1_REG_ASSERTION.TAG_ATTESTATION_BASIC_FULL)
    return getKeyfromCertificateBuffer(assertion.TAG_UAFV1_REG_ASSERTION.TAG_ATTESTATION_BASIC_FULL.TAG_ATTESTATION_CERT.b);

  else if (assertion.TAG_UAFV1_REG_ASSERTION.TAG_ATTESTATION_BASIC_SURROGATE)
    return getKeyFromAssertionBuffer(
      assertion.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_PUB_KEY.b,
      assertion.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_ASSERTION_INFO.algEncPub
    );
}


module.exports = {
  getRegistrationRequestTemplate: getRegistrationRequestTemplate,
  getDeregistrationRequestTemplate: getDeregistrationRequestTemplate,
  getAttestationPubKey: getAttestationPubKey
};