const crypto = require("crypto");
const base64url = require("base64url");
const cbor = require("cbor");
const jsrsasign = require("jsrsasign");

let gsr2 =
  "MIIDujCCAqKgAwIBAgILBAAAAAABD4Ym5g0wDQYJKoZIhvcNAQEFBQAwTDEgMB4GA1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjIxEzARBgNVBAoTCkdsb2JhbFNpZ24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDYxMjE1MDgwMDAwWhcNMjExMjE1MDgwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKbPJA6+Lm8omUVCxKs+IVSbC9N/hHD6ErPLv4dfxn+G07IwXNb9rfF73OX4YJYJkhD10FPe+3t+c4isUoh7SqbKSaZeqKeMWhG8eoLrvozps6yWJQeXSpkqBy+0Hne/ig+1AnwblrjFuTosvNYSuetZfeLQBoZfXklqtTleiDTsvHgMCJiEbKjNS7SgfQx5TfC4LcshytVsW33hoCmEofnTlEnLJGKRILzdC9XZzPnqJworc5HGnRusyMvo4KD0L5CLTfuwNhv2GXqF4G3yYROIXJ/gkwpRl4pazq+r1feqCapgvdzZX99yqWATXgAByUr6P6TqBwMhAo6CygPCm48CAwEAAaOBnDCBmTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUm+IHV2ccHsBqBt5ZtJot39wZhi4wNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5nbG9iYWxzaWduLm5ldC9yb290LXIyLmNybDAfBgNVHSMEGDAWgBSb4gdXZxwewGoG3lm0mi3f3BmGLjANBgkqhkiG9w0BAQUFAAOCAQEAmYFThxxol4aR7OBKuEQLq4GsJ0/WwbgcQ3izDJr86iw8bmEbTUsp9Z8FHSbBuOmDAGJFtqkIk7mpM0sYmsL4h4hO291xNBrBVNpGP+DTKqttVCL1OmLNIG+6KYnX3ZHu01yiPqFbQfXf5WRDLenVOavSot+3i9DAgBkcRcAtjOj4LaR0VknFBbVPFd5uRHg5h6h+u/N5GJG79G+dwfCMNYxdAfvDbbnvRG15RjF+Cv6pgsH/76tuIMRQyV+dTZsXjAzlAcmgQWpzU/qlULRuJQ/7TBj0/VLZjmmx6BEP3ojY+x1J96relc8geMJgEtslQIxq/H5COEBkEveegeGTLg==";

let hash = (alg, message) => {
  return crypto.createHash(alg).update(message).digest();
};

var parseAuthData = (buffer) => {
  let rpIdHash = buffer.slice(0, 32);
  buffer = buffer.slice(32);
  let flagsBuf = buffer.slice(0, 1);
  buffer = buffer.slice(1);
  let flagsInt = flagsBuf[0];
  let flags = {
    up: !!(flagsInt & 0x01),
    uv: !!(flagsInt & 0x04),
    at: !!(flagsInt & 0x40),
    ed: !!(flagsInt & 0x80),
    flagsInt,
  };

  let counterBuf = buffer.slice(0, 4);
  buffer = buffer.slice(4);
  let counter = counterBuf.readUInt32BE(0);

  let aaguid = undefined;
  let credID = undefined;
  let COSEPublicKey = undefined;

  if (flags.at) {
    aaguid = buffer.slice(0, 16);
    buffer = buffer.slice(16);
    let credIDLenBuf = buffer.slice(0, 2);
    buffer = buffer.slice(2);
    let credIDLen = credIDLenBuf.readUInt16BE(0);
    credID = buffer.slice(0, credIDLen);
    buffer = buffer.slice(credIDLen);
    COSEPublicKey = buffer;
  }

  return {
    rpIdHash,
    flagsBuf,
    flags,
    counter,
    counterBuf,
    aaguid,
    credID,
    COSEPublicKey,
  };
};

var getCertificateSubject = (certificate) => {
  let subjectCert = new jsrsasign.X509();
  subjectCert.readCertPEM(certificate);

  let subjectString = subjectCert.getSubjectString();
  let subjectFields = subjectString.slice(1).split("/");

  let fields = {};
  for (let field of subjectFields) {
    let kv = field.split("=");
    fields[kv[0]] = kv[1];
  }

  return fields;
};

var validateCertificatePath = (certificates) => {
  if (new Set(certificates).size !== certificates.length)
    throw new Error(
      "Failed to validate certificates path! Dublicate certificates detected!"
    );

  for (let i = 0; i < certificates.length; i++) {
    let subjectPem = certificates[i];
    let subjectCert = new jsrsasign.X509();
    subjectCert.readCertPEM(subjectPem);

    let issuerPem = "";
    if (i + 1 >= certificates.length) issuerPem = subjectPem;
    else issuerPem = certificates[i + 1];

    let issuerCert = new jsrsasign.X509();
    issuerCert.readCertPEM(issuerPem);

    console.log("subjectCert.getIssuerString()", subjectCert.getIssuerString());
    console.log("issuerCert.getSubjectString()", issuerCert.getSubjectString());

    if (subjectCert.getIssuerString() !== issuerCert.getSubjectString())
      throw new Error(
        "Failed to validate certificate path! Issuers dont match!"
      );

    let subjectCertStruct = jsrsasign.ASN1HEX.getTLVbyList(subjectCert.hex, 0, [
      0,
    ]);
    let algorithm = subjectCert.getSignatureAlgorithmField();
    let signatureHex = subjectCert.getSignatureValueHex();

    let Signature = new jsrsasign.crypto.Signature({ alg: algorithm });
    Signature.init(issuerPem);
    Signature.updateHex(subjectCertStruct);

    if (!Signature.verify(signatureHex))
      throw new Error("Failed to validate certificate path!");
  }

  return true;
};

let verifySafetyNetAttestation = (webAuthnResponse) => {
  console.log("webAuthnResponse", webAuthnResponse);

  let attestationBuffer = base64url.toBuffer(
    webAuthnResponse.response.attestationObject
  );
  let attestationStruct = cbor.decodeAllSync(attestationBuffer)[0];

  const authenticatorDataStruct = parseAuthData(attestationStruct.authData);

  let jwsString = attestationStruct.attStmt.response.toString("utf8");
  let jwsParts = jwsString.split(".");

  let HEADER = JSON.parse(base64url.decode(jwsParts[0]));
  let PAYLOAD = JSON.parse(base64url.decode(jwsParts[1]));
  let SIGNATURE = jwsParts[2];

  /* ----- Verify payload ----- */
  let clientDataHashBuf = hash(
    "sha256",
    base64url.toBuffer(webAuthnResponse.response.clientDataJSON)
  );

  let nonceBase = Buffer.concat([
    attestationStruct.authData,
    clientDataHashBuf,
  ]);

  let nonceBuffer = hash("sha256", nonceBase);
  let expectedNonce = nonceBuffer.toString("base64");

  if (PAYLOAD.nonce !== expectedNonce)
    throw new Error(
      `PAYLOAD.nonce does not contains expected nonce! Expected ${PAYLOAD.nonce} to equal ${expectedNonce}!`
    );

  if (!PAYLOAD.ctsProfileMatch)
    throw new Error("PAYLOAD.ctsProfileMatch is FALSE!");
  /* ----- Verify payload ENDS ----- */

  /* ----- Verify header ----- */
  let certPath = HEADER.x5c.concat([gsr2]).map((cert) => {
    let pemcert = "";
    for (let i = 0; i < cert.length; i += 64)
      pemcert += cert.slice(i, i + 64) + "\n";

    return (
      "-----BEGIN CERTIFICATE-----\n" + pemcert + "-----END CERTIFICATE-----"
    );
  });

  if (getCertificateSubject(certPath[0]).CN !== "attest.android.com")
    throw new Error('The common name is not set to "attest.android.com"!');

  validateCertificatePath(certPath);
  /* ----- Verify header ENDS ----- */

  /* ----- Verify signature ----- */
  let signatureBaseBuffer = Buffer.from(jwsParts[0] + "." + jwsParts[1]);
  let certificate = certPath[0];
  let signatureBuffer = base64url.toBuffer(SIGNATURE);

  let signatureIsValid = crypto
    .createVerify("sha256")
    .update(signatureBaseBuffer)
    .verify(certificate, signatureBuffer);

  if (!signatureIsValid) throw new Error("Failed to verify the signature!");

  const publicKey = COSEECDHAtoPKCS(authenticatorDataStruct.COSEPublicKey);

  /* ----- Verify signature ENDS ----- */

  //return true;
  return {
    verifed: signatureIsValid,
    authrInfo: {
      fmt: "android-safetynet",
      publicKey: base64url(publicKey),
      counter: authenticatorDataStruct.counter,
      credID: base64url(authenticatorDataStruct.credID),
    },
  };
};

module.exports = {
  verifySafetyNetAttestation,
};
