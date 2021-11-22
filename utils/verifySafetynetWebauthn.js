const crypto = require("crypto");
const base64url = require("base64url");
const cbor = require("cbor");
const jsrsasign = require("jsrsasign");

let gsr2 =
  "MIIETDCCAzSgAwIBAgILBAAAAAABL07hSVIwDQYJKoZIhvcNAQEFBQAwVzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNVBAsTB1Jvb3QgQ0ExGzAZBgNVBAMTEkdsb2JhbFNpZ24gUm9vdCBDQTAeFw0wNjEyMTUwODAwMDBaFw0yODAxMjgxMjAwMDBaMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFIyMRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9iYWxTaWduMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAps8kDr4ubyiZRULEqz4hVJsL03+EcPoSs8u/h1/Gf4bTsjBc1v2t8Xvc5fhglgmSEPXQU977e35ziKxSiHtKpspJpl6op4xaEbx6guu+jOmzrJYlB5dKmSoHL7Qed7+KD7UCfBuWuMW5Oiy81hK561l94tAGhl9eSWq1OV6INOy8eAwImIRsqM1LtKB9DHlN8LgtyyHK1WxbfeGgKYSh+dOUScskYpEgvN0L1dnM+eonCitzkcadG6zIy+jgoPQvkItN+7A2G/YZeoXgbfJhE4hcn+CTClGXilrOr6vV96oJqmC93Nlf33KpYBNeAAHJSvo/pOoHAyECjoLKA8KbjwIDAQABo4IBIjCCAR4wDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFJviB1dnHB7AagbeWbSaLd/cGYYuMEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzAzBgNVHR8ELDAqMCigJqAkhiJodHRwOi8vY3JsLmdsb2JhbHNpZ24ubmV0L3Jvb3QuY3JsMD0GCCsGAQUFBwEBBDEwLzAtBggrBgEFBQcwAYYhaHR0cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vcm9vdHIxMB8GA1UdIwQYMBaAFGB7ZhpFDZfKiVAvfQTNNKj//P1LMA0GCSqGSIb3DQEBBQUAA4IBAQCZIivuijLTDAd+3RsgK1BqlpEG2r5u13KWrVM/fvWPQufQ62SlZfLz4z0/WzEMfHmEOpeMDx+uwbzy67ig70H9vDGp/MlC5kS+HlbKdYuySTGZ/urpcWSGeo/l1WERQ+hAuzEM4tsYi5l0OGGrJICM+ag710nWZooYc8y8BjmLEDIODdOx9+9mExBZSMjPAcqZzJBymNs67cunu+JscI6mnmhj7Y+3LQWJztlU9k6rHkbbMEk/9mrgAfC8zYTUOfdVjgMVcdOdNO2dxtHIqsWEOTsN/SknUh6Dq0gjhVhQs5XGC7Mm4xYtqDDcA1BtXNEMzSqhR5rPIBvbQ4gfwvzg";

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
