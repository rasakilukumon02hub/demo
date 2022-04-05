import {
  getDatabase,
} from './data-mongo'

let uafDb;

let facets;
let policies;
let challenges;
let metadatas;
let authenticators;

function connect() {
  uafDb = getDatabase(process.env.MONGODB_FIDO_UAF_DB_NAME);

  facets = getCollection('facets');
  policies = getCollection('policies');
  challenges = getCollection('challenges');
  metadatas = getCollection('metadatas');
  authenticators = getCollection('authenticators');
}

function findOneTrustedFacetList(query) {
  const promise = new Promise(function(resolve, reject) {
    console.log("Searching for trusted facet list (TFL).");
    facets.find(query).toArray(function(err, facetListArray) {
      if (err) reject(err);
      if (!(facetListArray) || facetListArray.length === 0) reject(new Error(`TFL search using appID '${query.appID}' did not yield any matches.`));
      else resolve(facetListArray[0].trustedFacets);
    });
  });
  return promise;
}

function findOnePolicy(query) {
  const promise = new Promise(function(resolve, reject) {
    console.log("Searching for policy.");
    policies.find(query).toArray(function(err, policyArray) {
      if (err) reject(err);
      if (!(policyArray) || policyArray.length !== 1) reject(new Error("Policy search did not yield exactly one match."));
      else resolve(policyArray[0].policy);
    });
  });
  return promise;
}

function findAndDeleteChallenge(query) {
  const promise = new Promise(function(resolve, reject) {
    console.log("Searching for challenge.");
    challenges.findOneAndDelete(query, function(err, challenge) {
      if (err) reject(err);
      if (!(challenge) || !(challenge.value)) reject(new Error("No matching challenge found.")); // TODO: are both of these conditions possible, i.e., a challenge without a value?
      else resolve(challenge);
    });
  });
  return promise;
}

// NOTE: the syntax for update() below sets a createdAt column so we can take advantage of MongoDB TTL feature
//        the automatic removal of expired challenges requires an index:   collection.createIndex( { "createdAt": 1 }, { expireAfterSeconds: 60 } );
//        the TTL monitor runs every 60 seconds, so faster is not necessary (or useful)
//        the $currentDate update operator is only available then; we want system time to avoid issues with bad local time

function saveChallenge(challenge) {
  const promise = new Promise(function(resolve, reject) {
    console.log("Saving challenge.");
    challenges.update({
      challenge: challenge.challenge
    }, {
      $currentDate: {
        createdAt: true
      },
      $set: challenge
    }, {
      upsert: true
    }, function(err, result) {
      if (err) reject(err);
      resolve(result);
    });
  });
  return promise;
}

function findExactlyOneMetadata(query) {
  const promise = new Promise(function(resolve, reject) {
    console.log("Searching for metadata.");
    metadatas.find(query).toArray(function(err, metadataArray) {
      if (err) reject(err);
      if (!(metadataArray) || metadataArray.length !== 1) reject(new Error("Metadata search did not yield exactly one match."));
      else resolve(metadataArray[0]);
    });
  });
  return promise;
}

function findAuthenticators(query, modifier) {
  const promise = new Promise(function(resolve, reject) {
    console.log("Searching for authenticators.");
    authenticators.find(query, modifier).toArray(function(err, authenticatorArray) {
      if (err) reject(err);
      //      if (devices.length === 0) reject(new Error("No matching authenticators found."));
      else resolve(authenticatorArray);
    });
  });
  return promise;
}

function updateAuthenticator(query, update) {
  const promise = new Promise(function(resolve, reject) {
    console.log("Updating authenticator.");
    authenticators.updateOne(query, update, function(err, result) {
      if (err) reject(err);
      else resolve(result);
    });
  });
  return promise;
}

function saveAuthenticator(authenticator) {
  const promise = new Promise(function(resolve, reject) {
    console.log("Saving registered authenticator.");
    authenticators.insertOne(authenticator, {
      j: true
    }, function(err, result) {
      if (err) reject(err);
      else resolve(result);
    });
  });
  return promise;
}

function deleteAuthenticators(query) {
  const promise = new Promise(function(resolve, reject) {
    console.log("Deleting authenticators.");
    authenticators.deleteMany(query, function(err, result) {
      if (err) reject(err);
      else resolve(result);
    });
  });
  return promise;
}

function getCollection(collectionString) {

  const collection = uafDb.collection(collectionString);

  if (collection != null) {
    console.log("Collection found (" + collectionString + ") for UAF Database.");
    return collection;
  }
  // TODO: else?

  throw new Error(`Collection not found (${collectionString}) for UAF Database.`);
}

module.exports = {
  connect: connect,

  findOneTrustedFacetList: findOneTrustedFacetList,
  findOnePolicy: findOnePolicy,

  findAndDeleteChallenge: findAndDeleteChallenge,
  saveChallenge: saveChallenge,

  findExactlyOneMetadata: findExactlyOneMetadata,

  findAuthenticators: findAuthenticators,
  updateAuthenticator: updateAuthenticator,
  saveAuthenticator: saveAuthenticator,
  deleteAuthenticators: deleteAuthenticators,
}