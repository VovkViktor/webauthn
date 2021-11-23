const crypto = require("crypto");
const base64url = require("base64url");
const cbor = require("cbor");
const jsrsasign = require("jsrsasign");

let gsr2 =
  "MIIDdTCCAl2gAwIBAgILBAAAAAABFUtaw5QwDQYJKoZIhvcNAQEFBQAwVzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNVBAsTB1Jvb3QgQ0ExGzAZBgNVBAMTEkdsb2JhbFNpZ24gUm9vdCBDQTAeFw05ODA5MDExMjAwMDBaFw0yODAxMjgxMjAwMDBaMFcxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMRAwDgYDVQQLEwdSb290IENBMRswGQYDVQQDExJHbG9iYWxTaWduIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDaDuaZjc6j40+Kfvvxi4Mla+pIH/EqsLmVEQS98GPR4mdmzxzdzxtIK+6NiY6arymAZavpxy0Sy6scTHAHoT0KMM0VjU/43dSMUBUc71DuxC73/OlS8pF94G3VNTCOXkNz8kHp1Wrjsok6Vjk4bwY8iGlbKk3Fp1S4bInMm/k8yuX9ifUSPJJ4ltbcdG6TRGHRjcdGsnUOhugZitVtbNV4FpWi6cgKOOvyJBNPc1STE4U6G7weNLWLBYy5d4ux2x8gkasJU26Qzns3dLlwR5EiUWMWea6xrkEmCMgZK9FGqkjWZCrXgzT/LCrBbBlDSgeF59N89iFo7+ryUp9/k5DPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRge2YaRQ2XyolQL30EzTSo//z9SzANBgkqhkiG9w0BAQUFAAOCAQEA1nPnfE920I2/7LqivjTFKDK1fPxsnCwrvQmeU79rXqoRSLblCKOzyj1hTdNGCbM+w6DjY1Ub8rrvrTnhQ7k4o+YviiY776BQVvnGCv04zcQLcFGUl5gE38NflNUVyRRBnMRddWQVDf9VMOyGj/8N7yy5Y0b2qvzfvGn9LhJIZJrglfCm7ymPAbEVtQwdpf5pLGkkeB6zpxxxYu7KyJesF12KwvhHhm4qxFYxldBniYUr+WymXUadDKqC5JlR3XC321Y9YeRq4VzW9v493kHMB65jUr9TU/Qr6cf9tveCX4XSQRjbgbMEHMUfpIBvFSDJ3gyICh3WZlXi/EjJKSZp4A==";

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

let COSEECDHAtoPKCS = (COSEPublicKey) => {
  /* 
     +------+-------+-------+---------+----------------------------------+
     | name | key   | label | type    | description                      |
     |      | type  |       |         |                                  |
     +------+-------+-------+---------+----------------------------------+
     | crv  | 2     | -1    | int /   | EC Curve identifier - Taken from |
     |      |       |       | tstr    | the COSE Curves registry         |
     |      |       |       |         |                                  |
     | x    | 2     | -2    | bstr    | X Coordinate                     |
     |      |       |       |         |                                  |
     | y    | 2     | -3    | bstr /  | Y Coordinate                     |
     |      |       |       | bool    |                                  |
     |      |       |       |         |                                  |
     | d    | 2     | -4    | bstr    | Private key                      |
     +------+-------+-------+---------+----------------------------------+
  */

  let coseStruct = cbor.decodeAllSync(COSEPublicKey)[0];
  let tag = Buffer.from([0x04]);
  let x = coseStruct.get(-2);
  let y = coseStruct.get(-3);

  return Buffer.concat([tag, x, y]);
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
