import express from 'express';
import fetch from 'node-fetch';
import { Account, EmailChallenge, UserDb, MongoConnection } from '@presidioidentity/cosmosdb-client'

import { generateChallengeAndSendEmail, verifyEmailChallengeAndDelete } from '../email'
import { UserError } from '../error'

const router = express.Router();

router.post('/register', async(req, res, next) => {
  try {
    if (!req.body.email)
      throw new UserError(400, 'Missing email');

    const mongoConnection = await MongoConnection.getInstanceAndStart(process.env.COSMOSDB_CONNECTION_URL);
    const userDb = await UserDb.getInstance(mongoConnection);

    let account;
    try {
      account = await userDb.findOneAccountByEmail(req.body.email);
    } catch (e) { // TODO specific errors
      account = new Account(req.body.email);
    };
    await userDb.saveAccount(account);

    await generateChallengeAndSendEmail(account.email);

    res.status(200).send();
  } catch (err) {
    console.error(err);
    next(err);
  };
});

router.post('/register/complete', async(req, res, next) => {
  try {
    if (!req.body.email)
      throw new UserError(400, 'Missing email');
    if (!req.body.secret)
      throw new UserError(400, 'Missing secret');
    if (await verifyEmailChallengeAndDelete(req.body.email, req.body.secret)) {
      const mongoConnection = await MongoConnection.getInstanceAndStart(process.env.COSMOSDB_CONNECTION_URL);
      const userDb = await UserDb.getInstance(mongoConnection);
      userDb.verifyAccountEmail(req.body.email);
      res.status(200).send(); // TODO: update to send ID token.
    } else {
      throw new UserError(400, 'Incorrect verificatioin code');
    }
  } catch (err) {
    console.error(err);
    next(err);
  };
});

router.post('/add_device', async(req, res, next) => {
  try {
    if (!req.body.id_token)
      throw new UserError(400, 'Missing id_token');
    if (!req.body.authn_token)
      throw new UserError(400, 'Missing authn_token');
  } catch (err) {
    console.error(err);
    next(err);
  };
});


module.exports = router;