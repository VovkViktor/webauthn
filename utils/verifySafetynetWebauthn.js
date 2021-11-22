const crypto = require("crypto");
const base64url = require("base64url");
const cbor = require("cbor");
const jsrsasign = require("jsrsasign");

let gsr2 =
  "MIIFqzCCBJOgAwIBAgIQeAMYP8ge/NV4mjRgSXjtUjANBgkqhkiG9w0BAQwFADBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0yMDA3MjgwMDAwMDBaFw0yOTAzMTgwMDAwMDBaMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIENsaWVudCBBdXRoZW50aWNhdGlvbiBSb290IFI0NTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAL4+s+Lkt6NB+EuZp9omZGvtrkmDUX1sYOCfC+87Osa06Ek7zW2kPhrVymPqg3cA4lq9Vmx8gcHw2+Za0Zt9bSKWKOya47q3XbYRPuR6xrgazwUh6Sg3ZfTkya3mXSQvSIY+328VziqypV7clQSS5Xgm+N9cNeG/hlNlk8sYmOPZ7DINygrw/1V5OB9dzJ3tzhW2WJ9OWuCx00kUGKwIYObPw30ijm8meUNxZuZHj4Q2pmwAUna0RF8a7yLEBjaC4xxWmj1S91MEUSgg0bN0LS1iNynDZLjl+qn1QKX+axTh/XMZmiEjsefMhqMcJEi1bDwhfxdT6WSuJRcs9rtEnjhn70m7W3LTFd01Ex9VRqNGSZqC9c980ex5gs5IK91W+hmtJbiLtnDXgqPnPa9uQaY9YM55T2rEySY5RL0Brx1hcfb18TVGJx4DGeAxeWxxUd/DdmUilR7Ta2m8EFkYkVfin2LpC462h4/hv4PNSliyEN3u4/wPHAFgfvY4alxyuXkd3ddDRx3u7e/8yKz7UiF/g4ZrvO7pdn5VC3ye3mRERBSuquclKjA2GvEnQ/Ct/qNF10fJgXYiXM6O/eoOQSO4+MT2zWWMy3aaPK1qgcRRvq2UDYwXkSgBLB5yElRRQqTrLA+UVCwlO5PDMYZkhqFsSOa9UFbMUKdqyF62+oWvAgMBAAGjggF3MIIBczAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwIwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUdYKqG7azjRmP/Kl5zD8CmvRPy9kwHwYDVR0jBBgwFoAUj/BLf6guRSSuTVD6Y5qL3uLdG7wwegYIKwYBBQUHAQEEbjBsMC0GCCsGAQUFBzABhiFodHRwOi8vb2NzcC5nbG9iYWxzaWduLmNvbS9yb290cjMwOwYIKwYBBQUHMAKGL2h0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L3Jvb3QtcjMuY3J0MDYGA1UdHwQvMC0wK6ApoCeGJWh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vcm9vdC1yMy5jcmwwRwYDVR0gBEAwPjA8BgRVHSAAMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMA0GCSqGSIb3DQEBDAUAA4IBAQA4jxxlLUInsGCt1eiAtDDCgLbkJQCBPOeXDp6AgtgE+QuE/TBFYobDuB5J/KRFHwYTXcKCruB8czX6EqRQGOCf+8qlyeCtsfUg34sAZ3FBq6sIVwGE5vGBqPPFH/WwSCx3EKQ1D+MeWN4kszHs8mR3Dg8ejfe3Kt642XW2gI9zjpvMCKVoWRi0H7WDpQ+T8U0Gbsrzddrz+0jYoqvIItk8lhbwg0pRb3SPEOWa9o7vclAGA6Vdpmv/ieNBQUdASdo5UX0KFBi0iWfUS9mbZZAlOF3645oGTQ/JoBHFN817vqCEXIgi5gP0dbywIY0Qzp4a+se4NCg/GTD106Hpkezg";

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

    console.log("__________________________________");
    console.log(
      "subjectCert || getIssuerString()",
      subjectCert.getIssuerString()
    );

    console.log(
      "issuerCert || getSubjectString()",
      issuerCert.getSubjectString()
    );
    console.log("__________________________________");

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
