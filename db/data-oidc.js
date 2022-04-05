import {
  CIBAError,
  UserNotFoundError
} from '../error';
import {
  getDatabase,
  toObjectId
} from './data-mongo'

let oidcDb;

// OIDC Auth
let metadatas;
let requests;
let jtis;

function connect() {
  oidcDb = getDatabase(process.env.MONGODB_OIDC_DB_NAME);
  metadatas = getCollection('metadatas');
  requests = getCollection('requests');
  jtis = getCollection('jtis');
}

function getMetadataById(clientId) {
  const promise = new Promise((resolve, reject) => {
    console.log('Searching for client metadata.');
    metadatas.findOne({
      client_id: clientId
    }, (err, metadata) => {
      if (err) reject(err);
      else if (!metadata) reject(new CIBAError(500, "Client metadata not found."));
      else resolve(metadata);
    });
  });
  return promise;
}

function saveAuthReq(authReq) {
  const promise = new Promise((resolve, reject) => {
    console.log('Saving authentication request.');
    requests.insertOne(authReq, {
      j: true
    }, (err, result) => {
      if (err) reject(err);
      else resolve(result);
    });
  });
  return promise;
}

function getAuthReqById(authReqId) {
  const promise = new Promise((resolve, reject) => {
    console.log('Searching for auth request.');
    requests.findOne({
      _id: toObjectId(authReqId)
    }, (err, req) => {
      if (err) reject(err);
      else if (!req) reject(new CIBAError(500, "Auth Request not found."));
      else resolve(req);
    });
  });
  return promise;
}

function updateAuthRequest(id, update) {
  const promise = new Promise(function(resolve, reject) {
    console.log("Updating auth request.");
    requests.updateOne({
      _id: toObjectId(id)
    }, update, function(err, result) {
      if (err) reject(err);
      else resolve(result);
    });
  });
  return promise;
}

function findJti(jti) {
  const promise = new Promise((resolve, reject) => {
    console.log('Searching for JWT Identifier.');
    jtis.findOne({
      jti: jti
    }, (err, result) => {
      if (err) reject(err);
      else resolve(result);
    });
  });
  return promise;
}

function saveJti(jtiObj) {
  const promise = new Promise((resolve, reject) => {
    console.log('Saving JWT Identifier with expiration time.');
    jtis.insertOne(jtiObj, {
      j: true
    }, (err, result) => {
      if (err) reject(err);
      else resolve(result);
    });
  });
  return promise;
}

function getCollection(collectionString) {
  const collection = oidcDb.collection(collectionString);

  if (collection != null) {
    console.log(`Collection found (${collectionString}) for OIDC Database.`);
    return collection;
  }

  throw new Error(`Collection not found (${collectionString}) for OIDC Database.`);
}



module.exports = {
  connect,
  getMetadataById,
  saveAuthReq,
  getAuthReqById,
  updateAuthRequest,
  findJti,
  saveJti,
};