import dotenv from 'dotenv';
import express from 'express';
import fs from 'fs';
import path from 'path';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import logger from 'morgan';
import https from 'https';
import account from './account';
import oidcCiba from './oauth';
import users from './users';
import clients from './clients';
import fido from './fido'
import jwkStore from './jwt/jwk-store';

import dataMongo from './db/data-mongo'
import dataFido2 from './db/data-fido2'
import dataOidc from './db/data-oidc'
import dataUaf from './db/data-uaf'
import dataUser from './db/data-user'
import dataClient from './db/data-client'

dotenv.config();
const app = express();

Promise.all([
    // Dropped RS256 and RS512 support since OpenId FAPI advises against it:
    // http://lists.openid.net/pipermail/openid-specs-fapi/2017-July/000481.html

    /* TODO: Add support for EdDSA signature.
    Add support for kty OKP
    Add curve generation support for Ed25519, Ed448

    */

    /* TODO: Add support for secp256k1 crv type.
    May be useful to support webauthn.
    */

    /** Signature keys * */
    jwkStore.generate('RSA', 2048, {
      alg: 'PS256',
      use: 'sig',
    }),
    jwkStore.generate('EC', 'P-256', {
      alg: 'ES256',
      use: 'sig',
    }),

    jwkStore.generate('RSA', 2048, {
      alg: 'PS512',
      use: 'sig',
    }),
    jwkStore.generate('EC', 'P-256', {
      alg: 'ES512',
      use: 'sig',
    }),

    /** Encryption keys * */

    // Consider dropping RSA-OAEP, and mandate SHA-256 system wide
    // jwkStore.generateKeys("RSA", 2048, { alg: "RSA-OAEP", use: "enc" }),

    jwkStore.generate('RSA', 2048, {
      alg: 'RSA-OAEP-256',
      use: 'enc',
    }),

    /* TODO: Add support ECDH encryption.
    Request pubkey from client, maybe via jwk_uri?
    Then, use elliptic or crypto.js to compute shared key with our private key and client pubkey.
    Then use crypto.js to cipher using AES, via specified AES alg.

    Keys below are currently not in use for end-to-end encryption. They are only used for
    encrypting access_tokens.

    For OKP key type, add curve support for X25519, X448
    */

    // TODO, for JWKs endpoint, filter out kid == "presidio-identity-auth-access"
    jwkStore.generate('EC', 'P-256', {
      alg: 'ECDH-ES',
      enc: 'A128CBC-HS256',
      use: 'enc',
      kid: 'presidio-identity-auth-access',
    }),

    jwkStore.generate('EC', 'P-256', {
      alg: 'ECDH-ES',
      enc: 'A256CBC-HS512',
      use: 'enc',
      kid: 'presidio-identity-auth-access',
    }),
  ])
  .then(() => {
    fs.writeFileSync(
      'keys.json',
      JSON.stringify(jwkStore.toJSON(true))
    );
  })
  .then(() => dataMongo.start())
  .then(() => Promise.all([
    dataFido2.connect(),
    dataOidc.connect(),
    dataUaf.connect(),
    dataUser.connect(),
  ]))
  .then(dataClient.startAndConnectClient)
  .then(() => {
    // Set up Express app
    console.log('setting up express');
    app.use(logger('dev'));
    app.use(bodyParser.json());
    app.use(bodyParser.urlencoded({
      extended: false
    }));
    app.use(cookieParser());
    app.use(express.static(path.join(__dirname, 'public')));
    app.use('/', oidcCiba);
    app.use('/users/', users);
    app.use('/fido', fido);
    app.use('/client', clients);
    app.use('/account', account);
    console.log('done setting routes');
  })
  .then(() => {
    // Configure Error Handling Middleware
    app.use(function(err, req, res, next) {
      console.error(err);

      const status = err.status ? err.status : 500;
      const returnMessage = {
        message: err.message,
        details: err.details,
      };

      return res.status(status).json(returnMessage);
    });
  })
  .catch((err) => console.error(err));

module.exports = app;