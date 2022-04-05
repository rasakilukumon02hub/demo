import forge from 'node-forge';

function getPemPrivateFromPkcs12Cert(pkcs12Cert) {
  const p12Buf = Buffer.from(pkcs12Cert, 'base64');
  const p12Der = forge.util.decode64(p12Buf.toString('base64'));
  const pkcs12Asn1 = forge.asn1.fromDer(p12Der);
  const pkcs12 = forge.pkcs12.pkcs12FromAsn1(pkcs12Asn1);

  const { key } = pkcs12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[
    forge.pki.oids.pkcs8ShroudedKeyBag
  ][0];

  const pemPrivate = forge.pki.privateKeyToPem(key);
  return pemPrivate;
}

function toWebsafeBase64(buf) {
  return buf.toString('base64').replace(/\//g,'_').replace(/\+/g,'-').replace(/=/g, '');
}

module.exports = {
  getPemPrivateFromPkcs12Cert,
  toWebsafeBase64: toWebsafeBase64,
};
