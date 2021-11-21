const crypto = require("crypto");
const base64url = require("base64url");
const cbor = require("cbor");
const elliptic = require("elliptic");

const COSEKEYS = {
  kty: 1,
  alg: 3,
  crv: -1,
  x: -2,
  y: -3,
  n: -1,
  e: -2,
};

const COSEKTY = {
  OKP: 1,
  EC2: 2,
  RSA: 3,
};

const COSERSASCHEME = {
  "-3": "pss-sha256",
  "-39": "pss-sha512",
  "-38": "pss-sha384",
  "-65535": "pkcs1-sha1",
  "-257": "pkcs1-sha256",
  "-258": "pkcs1-sha384",
  "-259": "pkcs1-sha512",
};

const COSECRV = {
  1: "p256",
  2: "p384",
  3: "p521",
};

const COSEALGHASH = {
  "-257": "sha256",
  "-258": "sha384",
  "-259": "sha512",
  "-65535": "sha1",
  "-39": "sha512",
  "-38": "sha384",
  "-37": "sha256",
  "-7": "sha256",
  "-8": "sha512",
  "-36": "sha512",
};

const rawPublicKeyToPEM = (rawPublicKey, algorithmOrCurve) => {
  let keyBuffer = undefined;
  switch (algorithmOrCurve) {
    case "p256":
      keyBuffer = Buffer.concat([
        Buffer.from(
          "3059301306072a8648ce3d020106082a8648ce3d030107034200",
          "hex"
        ),
        rawPublicKey,
      ]);
      break;
    case "p384":
      keyBuffer = Buffer.concat([
        Buffer.from("3076301006072a8648ce3d020106052b81040022036200", "hex"),
        rawPublicKey,
      ]);
      break;
    case "p521":
      keyBuffer = Buffer.concat([
        Buffer.from(
          "30819b301006072a8648ce3d020106052b8104002303818600",
          "hex"
        ),
        rawPublicKey,
      ]);
      break;
    case "RSA":
      if (rawPublicKey.length < 512) {
        // 2080 key
        let pkcsHeader = Buffer.from(
          "30820122300d06092a864886f70d01010105000382010f003082010a0282010100",
          "hex"
        );
        let pkcsEXP = Buffer.from("0203010001", "hex");

        if (rawPublicKey.length > 256) rawPublicKey = rawPublicKey.slice(1);

        keyBuffer = Buffer.concat([pkcsHeader, rawPublicKey, pkcsEXP]);
      } else if (rawPublicKey.length >= 512 || rawPublicKey.length === 513) {
        let pkcsHeader = Buffer.from(
          "30820222300d06092a864886f70d01010105000382020f003082020a0282020100",
          "hex"
        );
        let pkcsEXP = Buffer.from("0203010001", "hex");

        if (rawPublicKey.length > 512) rawPublicKey = rawPublicKey.slice(1);

        keyBuffer = Buffer.concat([pkcsHeader, rawPublicKey, pkcsEXP]);
      } else {
        throw new Error(
          "RSA Verification: Unsupported key size: " + rawPublicKey.length
        );
      }
      break;
  }

  let b64publicKey = keyBuffer.toString("base64");

  let PEMKey = "";
  for (let i = 0; i < Math.ceil(b64publicKey.length / 64); i++) {
    let start = 64 * i;

    PEMKey += b64publicKey.substr(start, 64) + "\n";
  }

  PEMKey =
    "-----BEGIN PUBLIC KEY-----\n" + PEMKey + "-----END PUBLIC KEY-----\n";

  return PEMKey;
};

const hash = (alg, message) => {
  return crypto.createHash(alg).update(message).digest();
};

const verifySignature = (
  signatureBuffer,
  messageBuffer,
  cosePublicKeyBuffer
) => {
  let pubKeyCose = cbor.decodeAllSync(cosePublicKeyBuffer)[0];
  let alg = pubKeyCose.get(COSEKEYS.alg);
  let hashAlg = COSEALGHASH[alg].toUpperCase();

  // Verify ECDSA
  if (pubKeyCose.get(COSEKEYS.kty) === COSEKTY.EC2) {
    let x = pubKeyCose.get(COSEKEYS.x);
    let y = pubKeyCose.get(COSEKEYS.y);
    let crv = COSECRV[pubKeyCose.get(COSEKEYS.crv)];

    let ansiPublicKey = Buffer.concat([Buffer.from([0x04]), x, y]);

    let pemPublicKey = rawPublicKeyToPEM(ansiPublicKey, crv);
    return crypto
      .createVerify(hashAlg)
      .update(messageBuffer)
      .verify(pemPublicKey, signatureBuffer);

    // Verify RSA
  } else if (pubKeyCose.get(COSEKEYS.kty) === COSEKTY.RSA) {
    let signingScheme = COSERSASCHEME[pubKeyCose.get(COSEKEYS.alg)];
    let pemPublicKey = rawPublicKeyToPEM(pubKeyCose.get(COSEKEYS.n), "RSA");

    let signScheme = "RSA-" + hashAlg;

    let verify = crypto.createVerify(signScheme);
    verify.update(messageBuffer);
    verify.end();

    return verify.verify(
      {
        key: pemPublicKey,
        padding: crypto.constants.RSA_PKCS1_PADDING,
        dsaEncoding: "ieee-p1363",
      },
      signatureBuffer
    );

    // Verify EDDSA
  } else if (pubKeyCose.get(COSEKEYS.kty) === COSEKTY.OKP) {
    let x = pubKeyCose.get(COSEKEYS.x);

    let eddsa = new elliptic.eddsa("ed25519");
    let key = eddsa.keyFromPublic(x.toString("hex"));

    return key.verify(messageBuffer, signatureBuffer.toString("hex"));
  }
};

module.exports = { verifySignature };
