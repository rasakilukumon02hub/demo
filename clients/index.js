import express from 'express';

import dataClient from '../db/data-client';
import { ClientError } from '../error';

import jwkStore from '../jwt/jwk-store';
import {
  authenticateClient,
  validateJwtPayload,
  verifyJwtAndGetPayload
} from '../jwt/jwt-verify';

const PI_AUD = 'https://auth.dev.presidioidentity.net/token';

const router = express.Router();

const IClient = {
  name: 'string',
  jwks_uri: 'string',
  auth_id: 'string'   // FK to AUTH.id
}

router.get('/', async (req, res, next) => {
  try {
      console.log(req.query);

      if (req.query.client_id) {
          const client = await dataClient.findClientById(req.query.client_id);
          console.log('client', client);
          // const client = await cursor.toArray();
          return res.status(200).json({client});
      } else {
          throw new SchemaError(400, `Missing required query parameter 'client_id'`);
      }
  } catch (err) {
      console.error(err);
      next(err);
  }
});

router.put('/', async (req, res, next) => {
  try {

    const body = req.body;

    // TODO: just use Typescript + Interfaces
    Object.keys(IClient).forEach(key => {
      if (!key in body)
          throw new ClientError(400, `Missing required key ${key}`);
      if (typeof(body[key]) !== IClient[key])
          throw new ClientError(400, `key ${key} needs to be of type ${IClient[key]} but is ${typeof(body[key])}`);
    });

    const result = await dataClient.saveClient(body);

    return res.status(200).json({result});
  } catch (err) {
      console.error(err);
      next(err);
  }
});

router.post('/', async (req, res, next) => {
  try {

    const body = req.body;

    // if (!req.query.client_id) throw new ClientError(400, 'Invalid client_id');
    // const metadata = await dataOidc.getMetadataById(req.query.client_id);

    // if (!req.query.client_assertion_type)
    //   throw new ClientError(400, 'Missing client_assertion_type');
    // if (req.query.client_assertion_type != 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer')
    //   throw new ClientError(400, 'Invalid client_assertion_type');
    // if (!req.query.client_assertion)
    //   throw new ClientError(400, 'Missing client_assertion');

    // const clientJwks = await getValidClientJwk(metadata);
    // await authenticateClient(PI_AUD, req.query.client_id, req.query.client_assertion, clientJwks);

    const result = await dataClient.updateClient(body.config)

    return res.status(200).json({result});
  } catch (err) {
      console.error(err);
      next(err);
  }
});

module.exports = router;