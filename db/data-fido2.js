import {
  getDatabase
} from './data-mongo'

let fido2Db;

let fido2Authenticators;
let assertion;
let metadata;
let reg;
let auth;
let cred;

function connect() {
  fido2Db = getDatabase(process.env.MONGODB_FIDO_2_DB_NAME);

  fido2Authenticators = getCollection('fido2Authenticators');

  assertion = getCollection('assertion');
  metadata = getCollection('metadata');
  reg = getCollection('reg');
  auth = getCollection('auth');
  cred = getCollection('cred');
}

// TODO: simplify this function and use separate function to handle object model
function insertAttestation(rpID, rpName, userId, username, displayName, alg, challenge, ec, authSel, att, ext, pKey, counter) {
  const promise = new Promise(function(resolve, reject) {
    if (ext != null) {
      ext = ext['example.extension'];
    }
    reg.insertOne({
      'rpID': rpID,
      'rpName': rpName,
      'user_id': userId,
      'username': username,
      'displayName': displayName,
      'alg': alg,
      'challenge': challenge,
      'excludeCredentials': ec,
      'authenticatorSelection': authSel,
      'attestation': att,
      'extensions': ext,
      'pKey': pKey,
      'counter': counter
    }, function(err, result) {
      if (err) reject(err);
      else resolve(result.ops);
    });
  });
  return promise;
}

function saveAuthenticator(authenticator) {
  const promise = new Promise(function(resolve, reject) {
    fido2Authenticators.insertOne(authenticator, {
      j: true
    }, function(err, result) {
      if (err) reject(err);
      else resolve(result);
    });
  });
  return promise;
}

function findChallenge(challenge) {
  const promise = new Promise(function(resolve, reject) {
    reg.findOne({
      'challenge': challenge
    }, (err, cArray) => {
      if (err) reject(err);
      else {
        resolve(cArray);
        console.log(cArray);
      }
    });
  });
  return promise;
}

function updateUser(query, update) {
  const promise = new Promise(function(resolve, reject) {
    reg.update(query, update, function(err, result) {
      if (err) reject(err);
      else resolve(result);
    });
  });
  return promise;
}

function insertAssertion(challenge, rpID, acID, acType, userVerification) {
  const promise = new Promise(function(resolve, reject) {
    auth.insertOne({
      'challenge': challenge,
      'rpID': rpID,
      'allowCredID': acID,
      'allowCredType': acType,
      'userVerification': userVerification
    }, function(err, result) {
      if (err) reject(err);
      else resolve(result.ops);
    });
  });
  return promise;
}

function authChallenge(challenge) {
  const promise = new Promise(function(resolve, reject) {
    auth.findOne({
      'challenge': challenge
    }, (err, resArray) => {
      if (err) reject(err);
      else resolve(resArray);
    });
  });
  return promise;
}

function saveAssertion(data) {
  const promise = new Promise(function(resolve, reject) {
    assertion.insertOne(data, {
      j: true
    }, function(err, result) {
      if (err) reject(err);
      else resolve(result);
    });
  });
  return promise;
}

function findMetadata(aaguid) {
  const promise = new Promise(function(resolve, reject) {
    metadata.findOne({
      'aaguid': aaguid
    }, (err, authArray) => {
      if (err) reject(err);
      else resolve(authArray);
    });
  });
  return promise;
}

function findReg(username) {
  const promise = new Promise(function(resolve, reject) {
    reg.findOne({
      'username': username
    }, (err, userArray) => {
      if (err) reject(err);
      else resolve(userArray);
    });
  });
  return promise;
}

function updateCount(query, update) {
  const promise = new Promise(function(resolve, reject) {
    reg.update(query, update, function(err, result) {
      if (err) reject(err);
      else resolve(result);
    });
  });
  return promise;
}

function insertCred(credID, pKey, signCount, finalAAGUID) {
  const promise = new Promise(function(resolve, reject) {
    cred.insertOne({
      'id': credID,
      'publicKey': pKey,
      'counter': signCount,
      'aaguid': finalAAGUID
    }, function(err, result) {
      if (err) reject(err);
      else resolve(result.ops);
    });
  });
  return promise;
}


function findCred(id) {
  const promise = new Promise(function(resolve, reject) {
    cred.findOne({
      'id': id
    }, (err, cArray) => {
      if (err) reject(err);
      else resolve(cArray);
    });
  });
  return promise;
}


function getCollection(collectionString) {
  const collection = fido2Db.collection(collectionString);

  if (collection != null) {
    console.log('Collection found (' + collectionString + '). for FIDO2 Database');
    return collection;
  }

  throw new Error(`Collection not found (${collectionString}) for FIDO2 Database.`);
}

module.exports = {
  connect: connect,
  insertAttestation: insertAttestation,
  saveAuthenticator: saveAuthenticator,
  findChallenge: findChallenge,
  updateUser: updateUser,
  insertAssertion: insertAssertion,
  authChallenge: authChallenge,
  saveAssertion: saveAssertion,
  findMetadata: findMetadata,
  findReg: findReg,
  updateCount: updateCount,
  insertCred: insertCred,
  findCred: findCred,
}