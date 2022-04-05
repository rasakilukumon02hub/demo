import {
  toObjectId
} from './data-mongo'

import {
  MongoClient,
  ObjectId,
} from 'mongodb';

let started = false;
let dbClient;
let clientDb;
let clients;

function startAndConnectClient(options) {
  if (started) return Promise.resolve();
  return new Promise((resolve, reject) => {
    MongoClient.connect(process.env.CLIENTDB_CONNECTION_URL, (err, result) => {
      if (err) reject(err);
      console.log('Connected to client database.');
      dbClient = result;
      started = true;
      clientDb = dbClient.db(process.env.MONGODB_CLIENT_DB_NAME);
      
      clients = getCollection('clients');

      resolve();
    });
  });
}

function saveClient(client) {
  const promise = new Promise((resolve, reject) => {
    console.log('Saving client.');
    clients.insertOne(client, { j: true }, (err, result) => {
      if (err) reject(err);
      else resolve(result.ops[0]);
    });
  });
  return promise;
}
  
function findClientById(id) {
  const promise = new Promise((resolve, reject) => {
    console.log(`Searching for client via id ${id}.`);
    clients.findOne({
      _id: toObjectId(id)
    }, (err, clientsReq) => {
      if (err) reject(err);
      else if (!clientsReq) reject();
      else resolve(clientsReq);
    });
  });
  return promise;
}

function getCollection(collectionString) {
  const collection = clientDb.collection(collectionString);

  if (collection != null) {
    console.log(`Collection found (${collectionString}) for Client Database.`);
    return collection;
  }

  throw new Error(`Collection not found (${collectionString}) for Client Database.`);
}

module.exports = {
  startAndConnectClient,
  saveClient,
  findClientById,
};