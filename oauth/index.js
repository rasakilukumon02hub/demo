import express from 'express';
import {
  JWS,
  JWK
} from 'node-jose';
import fetch from 'node-fetch';

import {
  v4 as uuidv4
} from 'uuid';
import fs from 'fs';

import dataOidc from '../db/data-oidc';
import dataUser from '../db/data-user';
import {
  CIBAError
} from '../error';
import jwkStore from '../jwt/jwk-store';
import {
  authenticateClient,
  validateJwtPayload,
  verifyJwtAndGetPayload
} from '../jwt/jwt-verify';


const router = express.Router();

const PI_AUD = 'https://auth.dev.presidioidentity.net/token';

function getValidClientJwk(clientMetadata) {
  const jwkUri = clientMetadata.jwks_uri;
  const alg = clientMetadata.backchannel_authentication_request_signing_alg;
  return fetch(jwkUri, {
      method: 'GET'
    })
    .then((response) => response.json())
    .then((json) => JWK.asKeyStore(json))
    .then((jwks) => jwks.all({
      alg: alg,
      use: "sig"
    })[0]);
}

function validateRequestAndCreateResponse(clientId, request, clientMetadata) {
  return getValidClientJwk(clientMetadata)
    .then((jwks) => verifyJwtAndGetPayload(request, jwks))
    .then((payload) => {
      const payloadJson = JSON.parse(payload.payload.toString('utf8'));
      const auhtRequestSchemaOverride = (baseSchema) => {
        const schema = {...baseSchema
        };
        schema.properties.scope = {
          type: 'string',
          pattern: '(^|[ ])openid($|[ ])', // Must included openid. space or start/end of string on both side.
        };
        schema.properties.redirect_uri = {
          type: 'string',
          enum: clientMetadata.redirect_uris,
        };
        schema.required.push('scope');
        schema.errorMessage.properties.sub = 'scope must include openid';
        schema.errorMessage.properties.sub = 'redirect_uri must be one of redirect_uris in metadata';
        return schema;
      }

      return validateJwtPayload(payloadJson, clientId, PI_AUD, auhtRequestSchemaOverride)
        .then(async() => {
          const ttl = 12 * 60 * 60; // 12 hours
          const authReq = {
            client_id: clientId,
            scope: payloadJson.scope,
            redirect_uri: payloadJson.redirect_uri,
            authenticated: false,
            authenticatorId: undefined,
            ttl,
          };
          const result = await dataOidc.saveAuthReq(authReq);
          const authReqId = result.insertedId.toHexString();
          const authSuccess = {
            auth_req_id: authReqId,
            redirect_uri: `presidioidentity://app/auth?auth_req_id=${authReqId}`,
            expires_in: ttl,
            interval: 5,
          };
          return authSuccess;
        });
    });
}

function checkAuthenticationRequest(authReqId) {
  return dataOidc.getAuthReqById(authReqId)
    .then((authReq) => {
      console.log(authReq);

      var authenticatorId = undefined;
      var error = undefined;
      if (!authReq) {
        error = "expired_token";
      } else if (authReq.authenticated) {
        authenticatorId = authReq.authenticatorId;
      } else {
        error = "authorization_pending";
      }
      return {
        authenticatorId: authenticatorId,
        error: error
      };
    }).catch((err) => {
      return {
        authenticatorId: undefined,
        error: "expired_token"
      };
    })
}

async function createSignature(alg, payload) {
  const ks = fs.readFileSync('keys.json');
  const jwks = await JWK.asKeyStore(ks.toString());
  const key = jwks.all({
    alg: alg,
    use: 'sig'
  })[0];
  const opt = {
    compact: true,
    jwk: key,
    fields: {
      typ: 'jwt'
    }
  };
  return JWS.createSign(opt, key)
    .update(JSON.stringify(payload))
    .final()
}

async function createIdToken(clientId, userId, deviceId, alg, ttl) {
  const numericDateNow = Math.round((new Date()).getTime() / 1000);
  const payload = {
    iss: 'https://auth.dev.presidioidentity.net/token',
    aud: clientId,
    exp: numericDateNow + ttl,
    nbf: numericDateNow,
    iat: numericDateNow,
    sub: userId,
    deviceId: deviceId,
    // TODO: consider adding
    // auth_time: numericDateNow,
    jti: uuidv4(),
  };
  return createSignature(alg, payload);
}

async function createAccessToken(clientId, alg, ttl) {
  // TODO (low prio): Generate JWK according to specs.
  // TODO: Create userinfo endpoint to exchange access token for user info
  const numericDateNow = Math.round((new Date()).getTime() / 1000);
  const payload = {
    iss: 'https://auth.dev.presidioidentity.net/token',
    aud: clientId,
    exp: numericDateNow + ttl,
    nbf: numericDateNow,
    iat: numericDateNow,
    // TODO: consider adding
    // auth_time: numericDateNow,
    jti: uuidv4(),
  };
  return createSignature(alg, payload);
}

function createRefreshToken() {
  // TODO (low prio): Generate JWK according to specs.
  // TODO: Create endpoint to exchange refresh token for access token
}

function validateToken(token) {
  // TODO (low prio): Decrypt the token, then validate the signature.
}

router.post('/auth', async(req, res, next) => {
  try {
    if (!req.body.client_id) throw new CIBAError(400, 'Invalid client_id');
    const metadata = await dataOidc.getMetadataById(req.body.client_id);

    if (!req.body.client_assertion_type)
      throw new CIBAError(400, 'Missing client_assertion_type');
    if (req.body.client_assertion_type != 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer')
      throw new CIBAError(400, 'Invalid client_assertion_type');
    // if (!req.query.client_assertion)
    //   throw new CIBAError(400, 'Missing client_assertion');

    const clientJwks = await getValidClientJwk(metadata);
    await authenticateClient(PI_AUD, req.body.client_id, req.body.client_assertion, clientJwks);

    const result = await validateRequestAndCreateResponse(req.body.client_id, req.body.request, metadata);

    return res.status(200).json(result);
  } catch (err) {
    console.error(err);
    next(err);
  }
});

router.post('/token', async(req, res, next) => {
  try {
    if (!req.body.client_id) throw new CIBAError(400, 'Invalid client_id');
    const metadata = await dataOidc.getMetadataById(req.body.client_id);
    if (!req.body.client_assertion_type)
      throw new CIBAError(400, 'Missing client_assertion_type');
    if (req.body.client_assertion_type != 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer')
      throw new CIBAError(400, 'Invalid client_assertion_type');
    if (!req.body.client_assertion)
      throw new CIBAError(400, 'Missing client_assertion');

    const ks = fs.readFileSync("pub.json");
    const jwks =  await JWK.asKeyStore(ks.toString());
    
    await authenticateClient(PI_AUD, req.body.client_id, req.body.client_assertion, jwks);

    if (req.body.grant_type !== 'urn:openid:params:grant-type:ciba'){
      if(req.body.grant_type == 'client_credentials'){
        const ttl = 12 * 60 * 60; // 12 hours
        const accessToken = await createAccessToken(req.body.client_id, metadata.id_token_signed_response_alg, ttl);
        return res.status(200).json({
          token_type: "Bearer",
          expires_in: ttl,
          accessToken: accessToken
        });
      }
    }
    if (!req.body.auth_req_id)
      throw new CIBAError(400, 'Missing auth_req_id');

    const {
      authenticatorId,
      error
    } = await checkAuthenticationRequest(req.body.auth_req_id);
    if (error) {
      return res.status(400).json({
        error: error
      });
    } else {
      const ttl = 12 * 60 * 60; // 12 hours
      const device = await dataUser.findDeviceByAuthenticatorId(authenticatorId);
      const user = await dataUser.findUserByDevice(device._id.valueOf());
      const idToken = await createIdToken(req.body.client_id, user._id.valueOf(), device._id.valueOf(), metadata.id_token_signed_response_alg, ttl);
      return res.status(200).json({
        token_type: "Bearer",
        expires_in: ttl,
        id_token: idToken
      });
    }
  } catch (err) {
    console.error(err);
    next(err);
  }
});

router.get('/jwks', (req, res, next) => res.json(jwkStore.toJSON()));

// .well-known/openid-configuration to return discovery.js

module.exports = router;