import {
  MongoClient,
  ObjectId,
} from 'mongodb';

let started = false;
let dbClient = null;

function start(options) {
  if (started) return Promise.resolve();
  return new Promise((resolve, reject) => {
    MongoClient.connect(process.env.MONGODB_CONNECTION_URL, (err, result) => {
      if (err) reject(err);
      console.log('Connected to database.');
      dbClient = result;
      started = true;
      resolve(result);
    });
  });
}

function stop() {
  if (started) {
    dbClient.close();
    console.log('Disconnected from database.');
    started = false;
    dbClient = null;
  }
}

function getDatabase(databaseName) {
  if (started) {
    return dbClient.db(databaseName);
  }
  throw new Error('MongoClient not started');
}

function toObjectId(id) {
  return ObjectId(id);
}

module.exports = {
  start,
  stop,
  getDatabase,
  toObjectId,
};