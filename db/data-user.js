import {
  UserNotFoundError
} from '../error';

import {
  getDatabase,
  toObjectId
} from './data-mongo'

let userDb;

let onboard;
let users;
let devices;

function connect() {
  userDb = getDatabase(process.env.MONGODB_USER_DB_NAME);

  onboard = getCollection('onboard');
  users = getCollection('users');
  devices = getCollection('devices');
}

function createOnboardReq(email, accountId) {
  const promise = new Promise((resolve, reject) => {
    console.log('Saving onboard request.');
    onboard.insertOne({
      email,
      accountId,
      authenticated: false,
      authenticatorId: undefined
    }, {
      j: true
    }, (err, result) => {
      if (err) reject(err);
      else resolve(result.ops[0]);
    });
  });
  return promise;
}

function findOnboardReqById(onboardId) {
  const promise = new Promise((resolve, reject) => {
    console.log('Searching for onboard request.');
    onboard.findOne({
      _id: toObjectId(onboardId)
    }, (err, onboardReq) => {
      if (err) reject(err);
      else if (!onboardReq) reject();
      else resolve(onboardReq);
    });
  });
  return promise;
}

function updateOnboardReq(id, update) {
  const promise = new Promise(function(resolve, reject) {
    console.log("Updating onboard request.");
    onboard.updateOne({
      _id: toObjectId(id)
    }, update, function(err, result) {
      if (err) reject(err);
      else resolve(result);
    });
  });
  return promise;
}


function createUser(email) {
  const promise = new Promise((resolve, reject) => {
    console.log('Saving user.');
    users.insertOne({
      emails: [email],
      devices: []
    }, {
      j: true
    }, (err, result) => {
      if (err) reject(err);
      else resolve(result.ops[0]);
    });
  });
  return promise;
}

function findUser(email) {
  const promise = new Promise((resolve, reject) => {
    console.log('Searching for User.');
    users.findOne({
      emails: email
    }, (err, user) => {
      if (err) reject(err);
      else if (!user) resolve(null);
      else resolve(user);
    });
  });
  return promise;
}

function findDeviceByAuthenticatorId(authenticatorId) {
  const promise = new Promise((resolve, reject) => {
    console.log('Searching for device via authentiactor ID.');
    devices.findOne({
      authenticatorId: authenticatorId
    }, (err, device) => {
      if (err) reject(err);
      else if (!device) resolve(null);
      else resolve(device);
    });
  });
  return promise;
}

function findUserByDevice(deviceId) {
  const promise = new Promise((resolve, reject) => {
    console.log('Searching for user via device.');
    users.findOne({
      devices: deviceId
    }, (err, user) => {
      if (err) reject(err);
      else if (!user) resolve(null);
      else resolve(user);
    });
  });
  return promise;
}

function addDeviceToUser(accountId, deviceId) {
  const promise = new Promise((resolve, reject) => {
    console.log('Adding device to user');
    users.update({
        _id: toObjectId(accountId)
      }, {
        $push: {
          devices: deviceId
        }
      },
      (err, result) => {
        if (err) reject(err);
        else resolve(result);
      });
  });
  return promise;
}

function addEmailToUser(accountId, email) {
  const promise = new Promise((resolve, reject) => {
    console.log('Adding emails to user');
    users.update({
        _id: toObjectId(accountId)
      }, {
        $push: {
          emails: email
        }
      },
      (err, result) => {
        if (err) reject(err);
        else resolve(result);
      });
  });
  return promise;
}

function createDevice(authenticatorId, encPubKey, encAlg) {
  const promise = new Promise((resolve, reject) => {
    console.log('Saving device.');
    devices.insertOne({
      // pushToken: pushToken,
      authenticatorId: authenticatorId,
      encPubKey: encPubKey,
      encAlg: encAlg,
    }, {
      j: true
    }, (err, result) => {
      if (err) reject(err);
      else resolve(result.ops[0]);
    });
  });
  return promise;
}

function getCollection(collectionString) {
  const collection = userDb.collection(collectionString);

  if (collection != null) {
    console.log(`Collection found (${collectionString}) for User Database.`);
    return collection;
  }

  throw new Error(`Collection not found (${collectionString}) for User Database.`);
}

module.exports = {
  connect,
  createOnboardReq,
  findOnboardReqById,
  updateOnboardReq,
  createUser,
  findUser,
  findUserByDevice,
  findDeviceByAuthenticatorId,
  addDeviceToUser,
  addEmailToUser,
  createDevice,
};