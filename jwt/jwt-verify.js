import { JWS, JWK } from 'node-jose';

import Ajv from 'ajv';
import AjvErrors from 'ajv-errors';

import { JWTError } from '../error';

const ajv = new Ajv({ allErrors: true });
AjvErrors(ajv);

export function validateJwtPayload(payload, iss, aud, overrideFunction) {
  return new Promise(async (resolve, reject) => {
    const numericDateNow = Math.round((new Date()).getTime() / 1000) + 60; // race condtion? One minute grace period.
    const baseSchema = {
      type: 'object',
      properties: {
        iss: { type: 'string', const: iss },
        aud: { type: 'string', const: aud },
        exp: { type: 'integer', minimum: numericDateNow },
        nbf: { type: 'integer', minimum: 0, maximum: numericDateNow },
        iat: { type: 'integer', minimum: 0, maximum: numericDateNow },
        jti: { type: 'string', minLength: 32, maxLength: 64 },
      },
      required: ['iss', 'aud', 'exp', 'nbf', 'iat'],

      errorMessage: {
        properties: {
          iss: 'iss must be the client_id',
          aud: 'aud must be the provider token endpoint',
          exp: 'exp must be a valid epoch time integer in the future',
          nbf: 'nbf must be a valid epoch time integer in the past',
          iat: 'nbf must be a valid epoch time integer in the past',
          jti: 'jti must be a single-use unique string with length between [32,64]',
        },
      },
    };

    const schema = overrideFunction ? overrideFunction(baseSchema) : baseSchema;

    const validate = ajv.compile(schema);
    const valid = validate(payload);

    if (valid) {
      // TODO check Mongo for unique jti.
      // TODO save jti object with expiration time.
      resolve();
    } else{
      throw new JWTError(400, 'JWT payload invalid', validate.errors);
    }
  });
}

export function verifyJwtAndGetPayload(jwt, jwk) {
  return JWS.createVerify(jwk).verify(jwt)
    .catch((err) => { throw new JWTError(400, 'JWK validation failed', err) });
}


export function authenticateClient(aud, clientId, clientAssertion, clientJwks) {
  verifyJwtAndGetPayload(clientAssertion, clientJwks)
    .then((payload) => {
      const payloadJson = JSON.parse(payload.payload.toString('utf8'));
      const clientAssertionSchemaOverride = (baseSchema) => {
        const schema = { ...baseSchema };
        schema.properties.sub = {
          type: 'string',
          const: clientId,
        };
        schema.required.push('sub');
        schema.errorMessage.properties.sub = 'sub must be the client_id';
        return schema;
      }

      return validateJwtPayload(payloadJson, clientId, aud, clientAssertionSchemaOverride)
        .catch((err) => {throw err;});
    }).catch((err) => {console.error(err); throw err});
}

function validateUniqueJti(jti, ttl) {
  // check if previous unexpired jti exists
  // save { _id : jti, ttl : exp }
}
