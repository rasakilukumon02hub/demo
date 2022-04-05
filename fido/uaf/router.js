import express from 'express';
import fetch from 'node-fetch';
import fs from 'fs';
import {
  JWS,
  JWK
} from 'node-jose';

import uaf from './uafLib'
import dataOidc from '../../db/data-oidc'
import dataUser from '../../db/data-user'
import dataUaf from '../../db/data-uaf'

const JWT_EXPIRATION_SECONDS = 60 * 60 * 24;
const router = express.Router();
let appID;


router.use(function(req, res, next) {
  appID = `${req.protocol}://${req.headers.host}/fido/uaf/`;
  next();
});

router.get("/", function(req, res, next) {

  dataUaf.findOneTrustedFacetList({
      appID: appID
    })
    .then(trustedFacetList => {
      res.type("application/fido.trusted-apps+json");
      res.json({
        trustedFacets: trustedFacetList
      });
    }).catch(next);
});

router.post("/get", function(req, res, next) { // /uaf/get
  if (req.body.context) {
    var uafRequestContext = JSON.parse(req.body.context);
    var username = uafRequestContext.username;
    var transaction = uafRequestContext.transaction;
    var serverData = uafRequestContext.interactionUuid;
  }

  switch (req.body.op) {

    case "Reg":
      { // TODO: parameterize policy
        uaf.startRegistration(appID, serverData, username)
        .then(result => sendRequest(res, result.uafRequest, "Reg"))
        .catch(next);
        break;
      }

    case "Auth":
      {
        uaf.startAuthentication(appID, serverData, username, transaction)
        .then(result => sendRequest(res, result.uafRequest, "Auth"))
        .catch(next);
        break;
      }

    case "Dereg":
      {
        const deregisterAll = uafRequestContext.deregisterAll ? uafRequestContext.deregisterAll : null;
        const deregisterAAID = uafRequestContext.deregisterAAID ? uafRequestContext.deregisterAAID : null;
        uaf.startDeregistration(appID, username, deregisterAll, deregisterAAID)
        .then(result => sendRequest(res, result.uafRequest, "Dereg"))
        .catch(next);
        break;
      }

    default:
      return next(new Error("Invalid operation selected: " + req.body.op));

  }

});

router.post("/respond", function(req, res, next) { // /uaf/respond
  const uafResponseArray = JSON.parse(req.body.uafResponse); // TODO: deal with bad req.body
  const uafResponse = uafResponseArray[0]; // TODO: deal with array properly
  switch (uafResponse.header.op) {

    case "Reg":
      { // TODO: parameterize policy
        uaf.finishRegistration(appID, uafResponse)
        .then(result => sendStatus(uafResponse.header.op, res, "Registration successful.", 1200, uafResponse, result.authenticatorId))
        .catch(next);
        break;
      }

    case "Auth":
      {
        uaf.finishAuthentication(appID, uafResponse)
        .then(result => sendStatus(uafResponse.header.op, res, "Authentication successful.", 1200, uafResponse, result.authenticatorId))
        .catch(next);
        break;
      }
    default:
      return next(new Error("Invalid operation selected: " + uafResponse.header.op));

  }
});

function sendRequest(res, request, op) { // TODO: consider pushing this into qrypto-uaf
  const returnUAFRequest = {
    statusCode: 1200,
    uafRequest: JSON.stringify(request),
    op: op,
    lifetimeMillis: 60000
  };
  res.type("application/fido+uaf; charset=utf-8");
  res.send(returnUAFRequest);
  res.end();
}

async function sendStatus(op, res, message, statusCode, uafResponse, authenticatorId) {

  const serverData = uafResponse.header.serverData;
  let redirect_uri;

  try {
    if (op === "Auth") {
      const authRequest = await dataOidc.getAuthReqById(serverData);
      if (authRequest) {
        redirect_uri = authRequest.redirect_uri;
        await dataOidc.updateAuthRequest(serverData, {
          $set: {
            authenticated: true,
            authenticatorId: authenticatorId,
          }
        })
      }
    } else if (op === "Reg") {
      const onboardRequest = await dataUser.findOnboardReqById(serverData);
      if (onboardRequest) {
        await dataUser.updateOnboardReq(serverData, {
          $set: {
            authenticated: true,
            authenticatorId: authenticatorId,
          }
        })
      }
    }
  } catch (e) {
    console.error(e);
  }

  const numericDateNow = Math.round((new Date()).getTime() / 1000); // seconds
  const payload = {
    iss: "auth.dev.presidioidentity.net",
    sub: authenticatorId,
    //    aud: "bartrack.com",                  // TODO: add information on context, i.e., OpenID Client ID?
    nbf: numericDateNow,
    iat: numericDateNow,
    exp: numericDateNow + JWT_EXPIRATION_SECONDS
  }

  const auth_token = await createSignature('ES256', payload)

  res.cookie("auth_token", auth_token);
  res.json({
    statusCode: statusCode,
    redirect_uri: redirect_uri,
    auth_token: auth_token
  });

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

module.exports = router;