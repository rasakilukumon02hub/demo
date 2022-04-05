import constants from './constants';
import {
  toWebsafeBase64
} from '../../util'
import {
  UAFError
} from '../../error'
import Ajv from 'ajv';


var ajv = new Ajv({
  v5: true
});
var bufferLengthDefinition = {
  errors: false,
  compile: function(values, parentSchema) {
    return function(data) {
      if (!(data instanceof Buffer)) return false;
      return (data.length >= values[0] && data.length <= values[1]);
    };
  }
};
ajv.addKeyword('bufferLength', bufferLengthDefinition);

function getResponseSchema() {

  var schema = { // TODO: modularize schemas for readability
    type: 'object',
    properties: {
      header: {
        type: 'object',
        properties: {
          upv: {
            type: 'object',
            properties: {
              major: {
                type: 'number',
                const: 1
              },
              minor: {
                type: 'number',
                const: 1
              }
            },
            required: ['major', 'minor']
          },
          serverData: {
            type: 'string',
            maxLength: 1536
          },
          appID: {
            type: 'string',
            maxLength: 512
          },
          op: {
            type: 'string',
            enum: ['Reg', 'Auth', 'Dereg']
          }
        },
        required: ['upv', 'serverData', 'appID', 'op']
      },
      fcParams: {
        type: 'string'
      },
      assertions: {
        type: 'array',
        minItems: 1,
        maxItems: 1,
        items: {
          type: 'object',
          properties: {
            assertion: {
              type: 'string',
              maxLength: 5462
            }, // NB: 4096 * 4/3 = 5461.33 (underlying string base64 of assertion)
            assertionScheme: {
              const: 'UAFV1TLV'
            }, // TODO: support comparison with metadata.assertionScheme (once more values are supported)
            tcDisplayPNGCharacteristics: { // from auth metadata spec
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  width: {
                    type: 'integer',
                    minimum: 0
                  },
                  height: {
                    type: 'integer',
                    minimum: 0
                  },
                  bitDepth: {
                    type: 'integer',
                    minimum: 0
                  }, // TODO: is this best 'octet' verification?
                  colorType: {
                    type: 'integer',
                    minimum: 0
                  },
                  compression: {
                    type: 'integer',
                    minimum: 0
                  },
                  filter: {
                    type: 'integer',
                    minimum: 0
                  },
                  interlace: {
                    type: 'integer',
                    minimum: 0
                  },
                  plte: {
                    type: 'array',
                    minItems: 1,
                    items: {
                      type: 'object',
                      properties: {
                        r: {
                          type: 'integer',
                          minimum: 0,
                          maximum: 65535
                        },
                        g: {
                          type: 'integer',
                          minimum: 0,
                          maximum: 65535
                        },
                        b: {
                          type: 'integer',
                          minimum: 0,
                          maximum: 65535
                        }
                      },
                      required: ['r', 'g', 'b']
                    }
                  }
                },
                required: ['width', 'height', 'bitDepth', 'colorType', 'compression', 'filter', 'interlace']
              }
            },
            exts: { // from protocol spec
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  id: {
                    type: 'string',
                    minLength: 1,
                    maxLength: 32
                  },
                  data: {
                    type: 'string'
                  },
                  fail_if_unknown: {
                    type: 'boolean'
                  }
                },
                required: ['id', 'data', 'fail_if_unknown']
              }
            }
          },
          required: ['assertion', 'assertionScheme']
        }
      }
    },
    required: ['header', 'fcParams', 'assertions']
  };

  return schema;
}

function getFCParamsSchema() {

  var schema = {
    type: 'object',
    properties: {
      appID: {
        type: 'string',
        minLength: 1,
        maxLength: 512
      },
      facetID: {
        type: 'string',
        minLength: 1,
        maxLength: 512
      },
      challenge: {
        type: 'string',
        minLength: 11,
        maxLength: 86
      }, // base64 is 4/3 original, but padding makes this indeterminate (i.e., 65 gives you 86 too)
      //    channelBinding: {                                                         // TODO: support channel binding
      //      type: 'object', properties: {
      //        serverEndPoint: { type: 'string' },
      //        tlsServerCertificate: { type: 'string' },
      //        tlsUnique: { type: 'string' },
      //        cid_pubkey: { type: 'string' }
      //      }
      //      required: [ 'serverEndPoint', 'tlsServerCertificate', 'tlsUnique', 'cid_pubkey' ]
      //    },
      //    required: [ 'appID', 'facetID', 'challenge', 'channelBinding' ]
    },
    required: ['appID', 'facetID', 'challenge']
  };

  return schema;
}

function getAssertionSchema() {

  var schema = { // TODO: verify buffer length ranges below

    definitions: {
      TAG_AAID: {
        type: 'object',
        properties: {
          l: {
            type: 'number',
            const: 9
          },
          b: {
            bufferLength: [9, 9]
          },
          s: {
            type: 'string',
            minLength: 9,
            maxLength: 9
          }
        }
      },
      TAG_ASSERTION_INFO: {
        type: 'object',
        properties: {
          l: {
            type: 'number',
            enum: [5, 7]
          },
          b: {
            bufferLength: [5, 7]
          },
          authenticatorVersion: {
            type: 'number',
            minimum: 0
          },
          authenticationMode: {
            type: 'number',
            enum: constants.AUTHENTICATION_MODE
          },
          algEncSign: {
            type: 'number',
            enum: constants.UAF_ALG_SIGN
          },
          algEncPub: {
            type: 'number',
            enum: constants.UAF_ALG_KEY
          }
        },
        required: ['authenticatorVersion', 'authenticationMode', 'algEncSign'],
        if: {
          properties: {
            l: {
              const: 7
            }
          }
        },
        then: {
          required: ['algEncPub']
        }
      },
      TAG_FINAL_CHALLENGE: {
        type: 'object',
        properties: {
          l: {
            type: 'number'
          },
          b: {
            bufferLength: [0, 10000]
          } // TODO: fix this
        }
      },
      TAG_KEYID: {
        type: 'object',
        properties: {
          l: {
            type: 'number'
          },
          b: {
            bufferLength: [0, 10000]
          } // TODO: fix this
        }
      },
      TAG_COUNTERS: {
        type: 'object',
        properties: {
          l: {
            type: 'number',
            enum: [4, 8]
          },
          b: {
            bufferLength: [4, 8]
          },
          signatureCounter: {
            type: 'number',
            minimum: 0
          },
          registrationCounter: {
            type: 'number',
            minimum: 0,
            maximum: 1000000
          } // TODO: what is 'exceedingly high'?
        },
        required: ['signatureCounter'],
        if: {
          properties: {
            l: {
              const: 8
            }
          }
        },
        then: {
          required: ['registrationCounter']
        }
      },
      TAG_PUB_KEY: {
        type: 'object',
        properties: {
          l: {
            type: 'number'
          },
          b: {
            bufferLength: [0, 10000]
          } // TODO: fix this
        }
      },
      TAG_SIGNATURE: {
        type: 'object',
        properties: {
          l: {
            type: 'number'
          },
          b: {
            bufferLength: [0, 10000]
          } // TODO: fix this
        }
      },
      TAG_ATTESTATION_CERT: {
        type: 'object',
        properties: { // TODO: support some checking with metadata.attestationRootCertificates
          l: {
            type: 'number'
          },
          b: {
            bufferLength: [0, 10000]
          } // TODO: fix this
        }
      },
      TAG_AUTHENTICATOR_NONCE: {
        type: 'object',
        properties: {
          l: {
            type: 'number'
          },
          b: {
            bufferLength: [0, 10000]
          } // TODO: fix this
        }
      },
      TAG_TRANSACTION_CONTENT_HASH: {
        type: 'object',
        properties: {
          l: {
            type: 'number'
          },
          b: {
            bufferLength: [0, 10000]
          } // TODO: fix this
        }
      },
      TAG_UNKNOWN: {
        type: 'object'
      }
    },

    type: 'object',

    properties: {

      TAG_UAFV1_REG_ASSERTION: {
        type: 'object',
        properties: {
          l: {
            type: 'number'
          },
          TAG_UAFV1_KRD: {
            type: 'object',
            properties: {
              l: {
                type: 'number'
              },
              TAG_AAID: {
                '$ref': '#/definitions/TAG_AAID'
              },
              TAG_ASSERTION_INFO: {
                '$ref': '#/definitions/TAG_ASSERTION_INFO'
              },
              TAG_FINAL_CHALLENGE: {
                '$ref': '#/definitions/TAG_FINAL_CHALLENGE'
              },
              TAG_KEYID: {
                '$ref': '#/definitions/TAG_KEYID'
              },
              TAG_COUNTERS: {
                '$ref': '#/definitions/TAG_COUNTERS'
              },
              TAG_PUB_KEY: {
                '$ref': '#/definitions/TAG_PUB_KEY'
              }
            },
            required: ['TAG_AAID', 'TAG_ASSERTION_INFO', 'TAG_FINAL_CHALLENGE', 'TAG_KEYID', 'TAG_COUNTERS', 'TAG_PUB_KEY']
          },
          TAG_ATTESTATION_BASIC_FULL: {
            type: 'object',
            properties: {
              l: {
                type: 'number'
              },
              TAG_SIGNATURE: {
                '$ref': '#/definitions/TAG_SIGNATURE'
              },
              TAG_ATTESTATION_CERT: {
                '$ref': '#/definitions/TAG_ATTESTATION_CERT'
              }
            },
            required: ['TAG_SIGNATURE', 'TAG_ATTESTATION_CERT']
          },
          TAG_ATTESTATION_BASIC_SURROGATE: {
            type: 'object',
            properties: {
              l: {
                type: 'number'
              },
              TAG_SIGNATURE: {
                '$ref': '#/definitions/TAG_SIGNATURE'
              }
            },
            required: ['TAG_SIGNATURE']
          }
        },
        required: ['TAG_UAFV1_KRD'],
        oneOf: [{
          required: ['TAG_ATTESTATION_BASIC_FULL']
        }, {
          required: ['TAG_ATTESTATION_BASIC_SURROGATE']
        }]
      },

      TAG_UAFV1_AUTH_ASSERTION: {
        type: 'object',
        properties: {
          l: {
            type: 'number'
          },
          TAG_UAFV1_SIGNED_DATA: {
            type: 'object',
            properties: {
              l: {
                type: 'number'
              },
              TAG_AAID: {
                '$ref': '#/definitions/TAG_AAID'
              },
              TAG_ASSERTION_INFO: {
                '$ref': '#/definitions/TAG_ASSERTION_INFO'
              },
              TAG_AUTHENTICATOR_NONCE: {
                '$ref': '#/definitions/TAG_AUTHENTICATOR_NONCE'
              },
              TAG_FINAL_CHALLENGE: {
                '$ref': '#/definitions/TAG_FINAL_CHALLENGE'
              },
              TAG_TRANSACTION_CONTENT_HASH: {
                '$ref': '#/definitions/TAG_TRANSACTION_CONTENT_HASH'
              },
              TAG_KEYID: {
                '$ref': '#/definitions/TAG_KEYID'
              },
              TAG_COUNTERS: {
                '$ref': '#/definitions/TAG_COUNTERS'
              }
            },
            required: ['TAG_AAID', 'TAG_ASSERTION_INFO', 'TAG_AUTHENTICATOR_NONCE', 'TAG_FINAL_CHALLENGE', 'TAG_TRANSACTION_CONTENT_HASH', 'TAG_KEYID', 'TAG_COUNTERS']
          },
          TAG_SIGNATURE: {
            '$ref': '#/definitions/TAG_SIGNATURE'
          }
        },
        required: ['TAG_UAFV1_SIGNED_DATA', 'TAG_SIGNATURE']
      }

    },

    oneOf: [{
      required: ['TAG_UAFV1_REG_ASSERTION']
    }, {
      required: ['TAG_UAFV1_AUTH_ASSERTION']
    }]

  };

  return schema;

}

function parseAssertion(assertionBuffer, fields) {

  try {
    var result = parse(assertionBuffer);
  } catch (error) {
    if (error instanceof RangeError) throw new UAFError('Malformed assertion during parsing', 1498, null);
    else throw error;
  }

  return result;

}

function validateWithSchemaWithOverride(object, schema, overrideFunction) {

  if (overrideFunction) {
    overrideFunction(schema);
  }

  var validate = ajv.compile(schema);
  var valid = validate(object);

  if (valid) return valid;
  else throw new UAFError('Schema validation failed', 1498, validate.errors);

}

module.exports = {
  getResponseSchema: getResponseSchema,
  getFCParamsSchema: getFCParamsSchema,
  getAssertionSchema: getAssertionSchema,
  parseAssertion: parseAssertion,
  validateWithSchemaWithOverride: validateWithSchemaWithOverride
};

function parse(buffer) {

  var objs = {};

  do {
    var obj = parseTLV(buffer);
    var objName = Object.keys(obj)[0];
    objs[objName] = obj[objName];
    buffer = buffer.slice(4 + obj[objName].l);
  } while (buffer.length > 0);

  return objs;

}

function parseTLV(buffer) {

  var t = buffer.readUInt16LE();
  var l = buffer.readUInt16LE(2);
  var bufferNext = buffer.slice(4, 4 + l);

  var obj = {};
  var tName = constants.tags[t] || 'TAG_UNKNOWN';
  obj[tName] = {
    l: l
  };
  if (t & 0x1000) {
    var newObj = parse(bufferNext);
    for (var property in newObj) obj[tName][property] = newObj[property];
  } else {
    obj[tName].b = bufferNext;
    tagProc(tName, bufferNext, obj[tName]);
  }

  return obj
}

function tagProc(tagString, buffer, target) {

  switch (tagString) {
    case 'TAG_ATTESTATION_CERT':
      break;
    case 'TAG_SIGNATURE':
      break;
    case 'TAG_KEYID':
      target.s = toWebsafeBase64(buffer);
      break;
    case 'TAG_FINAL_CHALLENGE':
      break;
    case 'TAG_AAID':
      target.s = buffer.toString();
      break;
    case 'TAG_PUB_KEY':
      break;
    case 'TAG_COUNTERS':
      if (buffer.length === 4 || buffer.length === 8) {
        target.signatureCounter = buffer.readUInt32LE();
        if (buffer.length === 8) target.registrationCounter = buffer.readUInt32LE(4);
        break;
      }
      break;
    case 'TAG_ASSERTION_INFO':
      if (buffer.length === 5 || buffer.length === 7) {
        target.authenticatorVersion = buffer.readUInt16LE();
        target.authenticationMode = buffer.readUInt8(2);
        target.algEncSign = buffer.readUInt16LE(3);
        if (buffer.length == 7) target.algEncPub = buffer.readUInt16LE(5);
        break;
      }
      break;
    case 'TAG_AUTHENTICATOR_NONCE':
      break;
    case 'TAG_TRANSACTION_CONTENT_HASH':
      break;
    default:
      break;
  }

}