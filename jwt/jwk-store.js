import { JWK } from 'node-jose';

// TODO: Consider migrating to Azure Keyvaults to support distributed nodes,
//       For Azure: Need to add key rotations, because keys are now rotated on deploy.
// TODO: Consider expanding this to its own Node package, so multiple services can use it.
// TODO: Consider adding key wrapping support
// TODO: Consider building all from crypto-js
// TODO: Consider building own JOSE formatter using base64url + crypto.js + keyvault to store keys

const instance = JWK.createKeyStore();

export default instance;
