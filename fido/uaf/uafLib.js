import crypto from 'crypto'

import uafRegistration from './registration';
import uafAuthentication from './authentication';
import uafResponse from './response';
// import uafTransaction from './transaction';
import uafCrypto from './uafcrypto';
import constants from './constants';

import {
  UAFError
} from '../../error'
import {
  toWebsafeBase64
} from '../../util'

import dataUaf from '../../db/data-uaf'


async function startRegistration(appID, serverData, username) {
  console.log('Registration request requested.');
  const policy = await dataUaf.findOnePolicy({
    name: 'policy0'
  });
  const authenticators = await dataUaf.findAuthenticators({
    username: username,
    type: 'uaf'
  }, {
    'data.aaid': 1,
    'data.keyID': 1
  });

  const uafRequest = getRegistrationRequest(appID, policy, authenticators, username, serverData);
  const challenge = extractChallengeFromRequest(uafRequest[0]);
  await dataUaf.saveChallenge(challenge);

  return {
    uafRequest: uafRequest,
    challenge: challenge.challenge
  };

}

async function startAuthentication(appID, serverData, username, transaction) {

  if (!transaction) console.log('Authentication request without transaction requested.');
  else console.log('Authentication request with transaction requested.');

  const policy = await dataUaf.findOnePolicy({
    name: 'policy0'
  });

  if (username != null) {
    var authenticators = await dataUaf.findAuthenticators({
      username: username,
      type: 'uaf'
    }, {
      'data.aaid': 1,
      'data.tcDisplayPNGCharacteristics': 1,
      'data.keyID': 1
    });
    if (!authenticators[0]) throw new Error('No suitable authenticators found.');
    var metadata = await dataUaf.findExactlyOneMetadata({
      aaid: authenticators[0].data.aaid,
      'upv.major': 1,
      'upv.minor': 1
    });
  } else {
    if (transaction) throw new Error('Missing username with transaction mode authentication.');
    var authenticators;
    var metadata;
    console.log('Authenticating without username.');
  }

  const uafRequest = getAuthenticationRequest(appID, policy, transaction, authenticators, metadata, serverData);
  const challenge = extractChallengeFromRequest(uafRequest[0]);
  await dataUaf.saveChallenge(challenge);

  return {
    uafRequest: uafRequest,
    challenge: challenge.challenge
  };

}

async function startDeregistration(appID, username, deregisterAll, deregisterAAID) {

  console.log('Deregistration request requested.');

  const queryParameters = {
    username: username,
    type: 'uaf'
  }
  if (deregisterAAID) {
    if (deregisterAAID.match(/^[0-9A-Fa-f]{4}#[0-9A-Fa-f]{4}$/)) queryParameters['data.aaid'] = deregisterAAID;
    else throw new Error(`UAF: Bad AAID format specified in 'context.deregisterAAID':'$(deregisterAAID)' .`);
  }
  const authenticators = await dataUaf.findAuthenticators(queryParameters, {
    'data.aaid': 1,
    'data.keyID': 1
  });
  const uafRequest = getDeregistrationRequest(appID, authenticators, deregisterAll, deregisterAAID);
  await dataUaf.deleteAuthenticators({
    '_id': {
      '$in': authenticators.map(authenticator => authenticator._id)
    }
  });

  return {
    uafRequest: uafRequest
  };

}


async function finishRegistration(appID, uafResponse) {

  console.log('Registration response received.');
  const trustedFacets = await dataUaf.findOneTrustedFacetList({
    appID: appID
  });
  //const trustedFacets = await dataUaf.findOneTrustedFacetList({ appID: uafResponse.header.appID, 'trustedFacets.version': uafResponse.header.upv }, { 'trustedFacets': { $elemMatch: { version: uafResponse.header.upv }}});
  const response = validateAndUnwrapResponse(['Reg'], trustedFacets[0].ids, uafResponse);
  const challenge = await dataUaf.findAndDeleteChallenge({
    challenge: response.fcParams.challenge
  });
  const metadata = await dataUaf.findExactlyOneMetadata({
    aaid: response.assertionObject.assertion.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_AAID.s,
    'upv.major': 1,
    'upv.minor': 1
  });
  const tcDisplayPNGCharacteristics = response.assertionObject.tcDisplayPNGCharacteristics != undefined ? response.assertionObject.tcDisplayPNGCharacteristics : metadata.tcDisplayPNGCharacteristics;
  if (metadata.tcDisplay != 0 && metadata.tcDisplayContentType === 'image/png' && tcDisplayPNGCharacteristics.length === 0) {
    throw new UAFError(`tcDisplay is non-zero but tcDisplayPNGCharacteristics is empty`, 1498, null);
  }
  const registrationData = verifyRegistrationAssertion(response.assertionObject, metadata);
  const saveResult = await dataUaf.saveAuthenticator({
    username: challenge.value.username,
    type: 'uaf',
    data: registrationData
  })

  console.log('Registration successful.');

  return {
    statusCode: 1200,
    authenticatorId: saveResult.insertedId.toHexString()
  };

}

async function finishAuthentication(appID, uafResponse) {

  console.log('Authentication response received.');
  const trustedFacets = await dataUaf.findOneTrustedFacetList({
    appID: appID
  });
  //const trustedFacets = await dataUaf.findOneTrustedFacetList({ appID: uafResponse.header.appID, 'trustedFacets.version': uafResponse.header.upv }, { 'trustedFacets': { $elemMatch: { version: uafResponse.header.upv }}});
  const response = validateAndUnwrapResponse(['Auth'], trustedFacets[0].ids, uafResponse);
  const challenge = await dataUaf.findAndDeleteChallenge({
    challenge: response.fcParams.challenge
  });
  const metadata = await dataUaf.findExactlyOneMetadata({
    aaid: response.assertionObject.assertion.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_AAID.s,
    'upv.major': 1,
    'upv.minor': 1
  });
  const tcDisplayPNGCharacteristics = response.assertionObject.tcDisplayPNGCharacteristics != undefined ? response.assertionObject.tcDisplayPNGCharacteristics : metadata.tcDisplayPNGCharacteristics;
  if (metadata.tcDisplay != 0 && metadata.tcDisplayContentType === 'image/png' && tcDisplayPNGCharacteristics.length === 0) {
    throw new UAFError(`tcDisplay is non-zero but tcDisplayPNGCharacteristics is empty`, 1498, null);
  }
  const authenticators = await dataUaf.findAuthenticators({
    'data.keyID': response.assertionObject.assertion.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_KEYID.s,
    type: 'uaf'
  }, {});
  verifyAuthenticationAssertion(response.assertionObject, challenge.value.transaction, authenticators[0], metadata);
  await dataUaf.updateAuthenticator({
    _id: authenticators[0]._id
  }, {
    '$set': {
      'data.signatureCounter': response.assertionObject.assertion.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_COUNTERS.signatureCounter
    }
  }); // TODO: verify this shouldn't be increment versus assignment

  console.log('Authentication successful.');

  return {
    statusCode: 1200,
    authenticatorId: authenticators[0]._id.toHexString()
  };

}

function getRegistrationRequest(appID, policy, authenticators, username, serverDataRaw = crypto.randomBytes(32)) {
  // TODO: enforce parameter validity
  var result = uafRegistration.getRegistrationRequestTemplate();

  result.uafRequest[0].header.appID = appID;
  result.uafRequest[0].header.serverData = toWebsafeBase64(serverDataRaw);
  result.uafRequest[0].challenge = toWebsafeBase64(crypto.randomBytes(32));
  result.uafRequest[0].username = username;

  if (authenticators && authenticators.length > 0) {
    if (!policy.disallowed) policy.disallowed = [];
    authenticators.forEach(authenticator => policy.disallowed.push({
      aaid: [authenticator.data.aaid],
      keyIDs: [authenticator.data.keyID]
    }));
  }

  result.uafRequest[0].policy = policy;

  return result.uafRequest; // TODO: remove array and just use single element? look at spec.

}

function getAuthenticationRequest(appID, policy, transaction, authenticators, metadata, serverDataRaw = crypto.randomBytes(32)) {
  // TODO: enforce parameter validity
  // TODO: use authenticator tcDisplayPNGCharacteristics to override metadata, if present.
  var result = uafAuthentication.getAuthenticationRequestTemplate();

  result.uafRequest[0].header.appID = appID;
  result.uafRequest[0].header.serverData = toWebsafeBase64(serverDataRaw); // TODO: do something with this field
  result.uafRequest[0].challenge = toWebsafeBase64(crypto.randomBytes(32));

  if (authenticators && authenticators.length > 0) {
    policy.accepted = [
      [{
        aaid: authenticators.map(authenticator => authenticator.data.aaid),
        keyIDs: authenticators.map(authenticator => authenticator.data.keyID)
      }]
    ];
  }

  result.uafRequest[0].policy = policy;

  if (transaction) {

    var contentType = metadata.tcDisplayContentType;
    var transactionObject = {
      contentType: contentType
    };

    switch (contentType) {
      case 'text/plain':
        transactionObject.content = toWebsafeBase64(Buffer.from(transaction));
        break;
      case 'image/png':
        // var tcDisplayPNGCharacteristics = metadata.tcDisplayPNGCharacteristics[0];
        // var transactionImageBuffer = uafTransaction.createImageFromText(transaction, tcDisplayPNGCharacteristics.width, tcDisplayPNGCharacteristics.height).toBuffer();
        // transactionObject.content = toWebsafeBase64(transactionImageBuffer);
        // transactionObject.tcDisplayPNGCharacteristics = tcDisplayPNGCharacteristics;
        // break;
      default:
        throw new UAFError(`Invalid metadata.tcDisplayContentType: ${contentType}.`, 1498, null);
    }

    result.uafRequest[0].transaction = [transactionObject];

  }

  return result.uafRequest; // TODO: remove array and just use single element? look at spec.

}

function getDeregistrationRequest(appID, authenticators, deregisterAll, deregisterAAID) {
  // TODO: enforce parameter validity
  const result = uafRegistration.getDeregistrationRequestTemplate();

  result.uafRequest[0].header.appID = appID;

  if (authenticators && authenticators.length > 0) {
    //result.uafRequest[0].authenticators = authenticators.map(authenticator => authenticator.data);
    let deregAuthenticators = null;
    if (deregisterAll) deregAuthenticators = [{
      aaid: '',
      keyID: ''
    }];
    else if (deregisterAAID) deregAuthenticators = [{
      aaid: deregisterAAID,
      keyID: ''
    }];
    else deregAuthenticators = authenticators.map(authenticator => ({
      aaid: authenticator.data.aaid,
      keyID: authenticator.data.keyID
    }));
    result.uafRequest[0].authenticators = deregAuthenticators;
  }

  console.log('deRegisterAll: ' + deregisterAll);
  console.log('deregisterAAID: ' + deregisterAAID);

  return result.uafRequest;

}


function validateAndUnwrapResponse(op, facetIDArray, response) {

  function overrideResponseSchema(schema) {
    schema.properties.header.properties.op.enum = op;
    schema.properties.header.properties.appID.enum = facetIDArray;
  }
  var result = validateResponse(response, overrideResponseSchema);
  if (result.error) throw result.error;

  function overrideFCParamsSchema(schema) {
    schema.properties.appID.enum = facetIDArray;
    schema.properties.facetID.enum = facetIDArray;
  }

  var fcParamsResult = getValidFCParamsFromResponse(response, overrideFCParamsSchema);
  if (fcParamsResult.error) throw fcParamsResult.error;

  var assertionResult = getAssertionFromValidResponse(response);
  if (assertionResult.error) throw (assertionResult.error);

  return {
    fcParams: fcParamsResult.value,
    assertionObject: assertionResult.value
  }

}


function verifyRegistrationAssertion(assertionObject, metadata) {

  function checkMetadata(assertion, metadata) {
    if (assertion.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_AAID.s !== metadata.aaid)
      throw new UAFError('Assertion failed metadata AAID check.', 1498, null);
    if (assertion.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_ASSERTION_INFO.authenticatorVersion < metadata.authenticatorVersion)
      throw new UAFError('Assertion failed metadata authenticatorVersion check.', 1498, null);
    if (assertion.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_ASSERTION_INFO.algEncSign !== metadata.authenticationAlgorithm)
      throw new UAFError('Assertion failed metadata authenticationAlgorithm check.', 1498, null);

    var i = 0;
    for (var attestationType of metadata.attestationTypes)
      if (assertion.TAG_UAFV1_REG_ASSERTION[constants.tags[attestationType]]) i++;
    if (i === 0) throw new UAFError('Assertion failed metadata attestationType check.', 1498, null);
  }

  var assertion = assertionObject.assertion;
  var assertionBuffer = assertionObject.assertionBuffer;
  var metadataValid = checkMetadata(assertionObject.assertion, metadata);
  var attestationPubKeyObject = uafRegistration.getAttestationPubKey(assertion); // TODO: verify certificate chain, also to include metadata
  var attestationObject = assertion.TAG_UAFV1_REG_ASSERTION.TAG_ATTESTATION_BASIC_FULL ||
    assertion.TAG_UAFV1_REG_ASSERTION.TAG_ATTESTATION_BASIC_SURROGATE;
  var algEncSign = assertion.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_ASSERTION_INFO.algEncSign;
  var signature = uafCrypto.getSignatureFromAssertionBuffer(attestationObject.TAG_SIGNATURE.b, algEncSign);
  var endIndex = assertion.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.l + 4 + 4; // note: length does given does NOT include T and L of TLV
  var signedData = assertionBuffer.slice(4, endIndex);

  var verify = uafCrypto.getVerifyMethodForKey(algEncSign);
  var check = verify.call(attestationPubKeyObject, signedData, signature);

  if (!check) throw new UAFError('Registration signature verification failed.', 1498, null);

  var pubKeyObject = uafCrypto.getKeyFromAssertionBuffer(assertion.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_PUB_KEY.b,
    assertion.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_ASSERTION_INFO.algEncPub);

  var registrationData = {
    pubKeyObject: pubKeyObject,
    keyID: assertion.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_KEYID.s,
    signatureCounter: assertion.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_COUNTERS.signatureCounter,
    authenticatorVersion: assertion.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_ASSERTION_INFO.authenticatorVersion,
    aaid: assertion.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_AAID.s
  };

  if (assertionObject.tcDisplayPNGCharacteristics) registrationData.tcDisplayPNGCharacteristics = assertionObject.tcDisplayPNGCharacteristics;
  if (assertionObject.exts) registrationData.exts = assertionObject.exts;

  return registrationData;

}


function verifyAuthenticationAssertion(assertionObject, transaction, authenticator, metadata) {

  var publicKeyObject = authenticator.data.pubKeyObject;
  var signatureCounter = authenticator.data.signatureCounter;

  function checkMetadata(assertion, metadata) {
    if (assertion.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_AAID.s !== metadata.aaid)
      throw new UAFError('Assertion failed metadata AAID check.', 1498, null);
    if (assertion.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_ASSERTION_INFO.authenticatorVersion < metadata.authenticatorVersion)
      throw new UAFError('Assertion failed metadata authenticatorVersion check.', 1498, null);
    if (assertion.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_ASSERTION_INFO.algEncSign !== metadata.authenticationAlgorithm)
      throw new UAFError('Assertion failed metadata authenticationAlgorithm check.', 1498, null);

    if (signatureCounter === 0) signatureCounter = -1; // combined with next statement: if a.sC = 0, assertion.sc >= 0; if a.sC > 0, assertion.sc > a.sC
    if (!(assertion.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_COUNTERS.signatureCounter > signatureCounter))
      throw new UAFError('Assertion failed authenticator signatureCounter check.', 1498, null);
  }

  var assertion = assertionObject.assertion;
  var assertionBuffer = assertionObject.assertionBuffer;
  var metadataValid = checkMetadata(assertionObject.assertion, metadata);
  var algEncSign = assertion.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_ASSERTION_INFO.algEncSign;
  var signature = uafCrypto.getSignatureFromAssertionBuffer(assertion.TAG_UAFV1_AUTH_ASSERTION.TAG_SIGNATURE.b, algEncSign);
  var endIndex = assertion.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.l + 4 + 4; // length does given does NOT include T and L of TLV
  var signedData = assertionBuffer.slice(4, endIndex);

  var verify = uafCrypto.getVerifyMethodForKey(algEncSign);
  var value = verify.call(publicKeyObject, signedData, signature);
  if (!value) throw new UAFError('Authentication signature verification failed.', 1498, null);

  if (assertion.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_ASSERTION_INFO.authenticationMode == 0x02) {
    if (!transaction) throw new UAFError('Missing transaction for Auth mode 0x02.', 1498, null);
    var rawTransaction = Buffer.from(transaction, 'base64');
    var transactionHash = crypto.createHash('SHA256').update(rawTransaction).digest();
    var check = transactionHash.equals(assertion.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_TRANSACTION_CONTENT_HASH.b);
    if (!check) throw new UAFError('Transaction hash verification failed.', 1498, null);
  }

}


module.exports = {

  startRegistration: startRegistration,
  startAuthentication: startAuthentication,
  startDeregistration: startDeregistration,

  finishRegistration: finishRegistration,
  finishAuthentication: finishAuthentication,
}

function extractChallengeFromRequest(uafRequest) {

  var challenge = {
    challenge: uafRequest.challenge, // TODO: eliminate UAFRequest top-level object
    serverData: uafRequest.header.serverData,
    username: uafRequest.username,
    policy: uafRequest.policy,
    expiration: 0
  }

  if (uafRequest.transaction) challenge.transaction = uafRequest.transaction[0].content; // TODO: handle arrays properly

  return challenge;

}

function validateResponse(response, overrideFunction) {

  try {
    var responseValid = uafResponse.validateWithSchemaWithOverride(response, uafResponse.getResponseSchema(), overrideFunction);
    return {
      error: null,
      value: responseValid
    };
  } catch (error) {
    if (error instanceof UAFError) return {
      error: error,
      value: null
    };
    else throw error;
  }

}

function getValidFCParamsFromResponse(response, overrideFunction) { // NOTE: add AJV keyword for Buffer.from(base64).length test

  try {
    var fcParams = JSON.parse(Buffer.from(response.fcParams, 'base64'));
    var fcParamsValid = uafResponse.validateWithSchemaWithOverride(fcParams, uafResponse.getFCParamsSchema(), overrideFunction);
    var challengeBuffer = Buffer.from(fcParams.challenge, 'base64');
    if (challengeBuffer.length > 64 || challengeBuffer.length < 8)
      throw new UAFError('UAF response validation failed', 1498, validate.errors);
    return {
      error: null,
      value: fcParams
    };
  } catch (error) {
    if (error instanceof UAFError) return {
      error: error,
      value: null
    };
    else throw error;
  }

}

function getAssertionFromValidResponse(response) {

  try {
    var assertionBuffer = Buffer.from(response.assertions[0].assertion, 'base64'); // TODO: deal properly with whole array
    var assertion = uafResponse.parseAssertion(assertionBuffer);
    var schema = uafResponse.getAssertionSchema();
    var assertionValid = uafResponse.validateWithSchemaWithOverride(assertion, schema, null);

    var fcHash = crypto.createHash('SHA256').update(response.fcParams).digest(); // TODO: SHA256 looks to be the only one supported at this point... will change implementation if that changes
    if (assertion.TAG_UAFV1_REG_ASSERTION)
      var finalChallenge = assertion.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_FINAL_CHALLENGE.b;
    else if (assertion.TAG_UAFV1_AUTH_ASSERTION)
      var finalChallenge = assertion.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_FINAL_CHALLENGE.b;
    var test = finalChallenge.equals(fcHash); // per spec Protocol 3.4.6.5, must be true
    if (!test) throw new UAFError('TAG_FINAL_CHALLENGE is NOT equal to hash of fcParams', 1498, null);

    var value = {
      assertion: assertion,
      assertionBuffer: assertionBuffer,
      tcDisplayPNGCharacteristics: response.assertions[0].tcDisplayPNGCharacteristics,
      exts: response.assertions[0].exts
    };

    return {
      error: null,
      value: value
    };
  } catch (error) {
    if (error instanceof UAFError) return {
      error: error,
      value: null
    };
    else throw error;
  }

}