import express from 'express';
import fetch from 'node-fetch';

import {
  v4 as uuidv4
} from 'uuid';
import fs from 'fs';

import dataUser from '../db/data-user';
import {
  UserError
} from '../error';

const router = express.Router();

router.post('/onboard', async(req, res, next) => {
  try {
    if (!req.query.email)
      throw new UserError(400, 'Missing email');

    let account = await dataUser.findUser(req.query.email);

    if (account !== null) {
      console.log('Account found for email');
    } else {
      // create an account
      // TODO: Create account only after email verification
      account = await dataUser.createUser(req.query.email);
    }

    const onboardReq = await dataUser.createOnboardReq(req.query.email, account._id.valueOf());

    return res.status(200).json({
      onboard_req_id: onboardReq._id.valueOf()
    });
  } catch (err) {
    console.error(err);
    next(err);
  }
});

router.post('/onboard/confirm-email', async(req, res, next) => {});


router.post('/onboard/complete', async(req, res, next) => {
  try {
    if (!req.query.onboard_req_id)
      throw new UserError(400, 'Missing onboardReqId');

    const onboardReq = await dataUser.findOnboardReqById(req.query.onboard_req_id);

    if (!onboardReq.authenticated || !onboardReq.authenticatorId)
      throw new UserError(400, 'Not authenticated');

    if (!req.query.enc_pub_key || !req.query.enc_alg)
      throw new UserError(400, 'Missing encryption key');

    const device = await dataUser.createDevice(onboardReq.authenticatorId, req.query.enc_pub_key, req.query.enc_alg);
    const result = await dataUser.addDeviceToUser(onboardReq.accountId, device._id.valueOf());

    return res.status(200).json({
      user_id: onboardReq.accountId,
      device_id: device._id.valueOf()
    });
  } catch (err) {
    console.error(err);
    next(err);
  }
});

module.exports = router;