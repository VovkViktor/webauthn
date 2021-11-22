const { User, validate, loginValidate } = require("../models/user");
const { AuthnKey } = require("../models/webAuthnKey");
const verify = require("./authVerify");
const bcrypt = require("bcrypt");
const express = require("express");
const jwt = require("jsonwebtoken");
const base64url = require("base64url");

const router = express.Router();
const {
  generateServerMakeCredRequest,
  verifyAuthenticatorAttestationResponse,
  verifyAuthenticatorAssertionResponse,
  generateServerGetAssertion,
} = require("../utils/webauthnHelpers");

router.post("/register", async (request, response) => {
  // First Validate The Request
  const resValid = validate(request.body);

  const { error } = resValid;
  if (error) {
    return response.status(400).send({ message: error.details[0].message });
  }
  // Check if this user already exists
  let user = await User.findOne({ email: request.body.email });

  if (user) {
    return response.status(400).send({ message: "That user already exists!" });
  } else {
    const salt = await bcrypt.genSalt(10);

    const hashedPassword = await bcrypt.hash(request.body.password, salt);

    try {
      // Insert the new user if they do not exist yet
      user = new User({
        email: request.body.email,
        password: hashedPassword,
      });

      const createdUser = await user.save();

      request.session.token = jwt.sign(
        {
          _id: createdUser._id,
        },
        process.env.TOKEN_SECRET
      );

      response.status(200).send({
        id: createdUser._id,
        email: createdUser.email,
        isPassword: !!createdUser.password,
      });
    } catch (e) {
      return response.status(500).send(e);
    }
  }
});

router.post("/login", async (request, response) => {
  const user = await User.findOne({ email: request.body.email });
  if (!user) return response.status(400).send({ message: "Incorrect Email" });

  const validPassword = await bcrypt.compare(
    request.body.password,
    user.password
  );

  if (!validPassword)
    return response.status(400).send({ message: "Incorrect Password" });

  try {
    const { error } = await loginValidate.validateAsync(request.body);
    if (error) {
      return response.status(400).send({ message: error.details[0].message });
    } else {
      request.session.token = jwt.sign(
        {
          _id: user._id,
        },
        process.env.TOKEN_SECRET
      );

      response.send({
        email: user.email,
        isPassword: !!user.password,
        id: user._id,
      });
    }
  } catch (e) {
    response.status(500).send(e); //
  }
});

router.post("/add-password", verify, async (request, response) => {
  const user = request.user;
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(request.body.password, salt);

  const result = await User.findByIdAndUpdate(user._id, {
    password: hashedPassword,
  }).exec();

  const updatedUser = await User.findById(result._id);

  try {
    response.send({
      email: updatedUser.email,
      isPassword: !!updatedUser.password,
      id: updatedUser._id,
    });
  } catch (e) {
    response.status(500).send(e); //
  }
});

router.get("/authn-keys", verify, async (request, response) => {
  try {
    const user = request.user;
    const result = await AuthnKey.find({ userId: user._id }, { __v: 0 }).exec();
    response.send(result);
  } catch (e) {
    return response.status(500).send(e);
  }
});

router.delete("/authn-key/delete/:id", verify, async (request, response) => {
  try {
    const keyId = request.params.id;
    const result = await AuthnKey.findByIdAndDelete(keyId);
    response.send(result);
  } catch (e) {
    return response.status(500).send(e);
  }
});

router.get("/howami", verify, async (request, response) => {
  try {
    const user = request.user;
    const result = await User.findById(user._id).exec();
    response.send({
      id: result._id,
      email: result.email,
      isPassword: !!result.password,
    });
  } catch (e) {
    response.status(500).send(e);
  }
});

router.post("/webauthn/create", async (request, response) => {
  let email = request.body.email;
  if (!email)
    return response.status(400).send({ message: "email is requared" });

  let user = await User.findOne({ email });
  if (user) {
    return response.status(400).send({
      status: "failed",
      message: `Username ${email} already exists`,
    });
  }

  let challengeMakeCred = generateServerMakeCredRequest(email, email);
  //challengeMakeCred.status = 'ok'

  request.session.challenge = challengeMakeCred.challenge;
  request.session.email = email;

  response.status(200).send(challengeMakeCred);
});

router.post("/webauthn/create/response", async (request, response) => {
  if (
    !request.body ||
    !request.body.id ||
    !request.body.rawId ||
    !request.body.response ||
    !request.body.type ||
    request.body.type !== "public-key"
  ) {
    return response.status(400).send({
      status: "failed",
      message:
        "Response missing one or more of id/rawId/response/type fields, or type is not public-key!",
    });
  }

  let webauthnResp = request.body;

  let clientData = JSON.parse(
    base64url.decode(webauthnResp.response.clientDataJSON)
  );

  /* Check challenge... */

  if (clientData.challenge !== request.session.challenge) {
    return response.status(400).send({
      status: "failed",
      message: "Challenges don't match!",
    });
  }
  /* ...and origin */
  if (clientData.origin !== "https://learnwebauthn-vb5r9.ondigitalocean.app") {
    response.status(400).json({
      status: "failed",
      message: "Origins don't match!",
      origin: clientData.origin,
    });
  }

  let result;
  if (webauthnResp.response.attestationObject !== undefined) {
    /* This is create cred */
    result = verifyAuthenticatorAttestationResponse(webauthnResp);
  } else if (webauthnResp.response.authenticatorData !== undefined) {
    /* This is get assertion */
    result = verifyAuthenticatorAssertionResponse(webauthnResp, [
      result.authrInfo,
    ]);
  } else {
    response.status(400).json({
      status: "failed",
      message: "Can not determine type of response!",
    });
  }

  if (result.verifed) {
    const newUser = new User({
      email: request.session.email,
      createAt: new Date(),
    });

    const newAuthnKey = new AuthnKey({
      userId: newUser._id,
      key: result.authrInfo,
    });

    await newUser.save();
    await newAuthnKey.save();

    request.session.token = jwt.sign(
      {
        _id: newUser._id,
      },
      process.env.TOKEN_SECRET
    );

    response.status(200).send({
      id: newUser._id,
      email: newUser.email,
      isPassword: !!newUser.password,
    });
  } else {
    return response.status(400).send({
      status: "failed",
      message: "Can not authenticate signature!",
    });
  }
});

router.get("/webauthn/create/key", verify, async (request, response) => {
  const { _id } = request.user;

  const user = await User.findById(_id);

  let challengeMakeCred = generateServerMakeCredRequest(user.email, user.email);

  request.session.challenge = challengeMakeCred.challenge;
  request.session.email = user.email;

  response.status(200).send(challengeMakeCred);
});

router.post(
  "/webauthn/create/key/response",
  verify,
  async (request, response) => {
    if (
      !request.body ||
      !request.body.id ||
      !request.body.rawId ||
      !request.body.response ||
      !request.body.type ||
      request.body.type !== "public-key"
    ) {
      return response.status(400).send({
        status: "failed",
        message:
          "Response missing one or more of id/rawId/response/type fields, or type is not public-key!",
      });
    }

    let webauthnResp = request.body;

    console.log("webauthnResp", webauthnResp);

    let clientData = JSON.parse(
      base64url.decode(webauthnResp.response.clientDataJSON)
    );

    /* Check challenge... */

    if (clientData.challenge !== request.session.challenge) {
      return response.status(400).send({
        status: "failed",
        message: "Challenges don't match!",
      });
    }
    /* ...and origin */
    if (
      clientData.origin !== "https://learnwebauthn-vb5r9.ondigitalocean.app"
    ) {
      response.status(400).send({
        status: "failed",
        message: "Origins don't match!",
      });
    }

    let result;
    if (webauthnResp.response.attestationObject !== undefined) {
      /* This is create cred */
      result = verifyAuthenticatorAttestationResponse(webauthnResp);
    } else if (webauthnResp.response.authenticatorData !== undefined) {
      /* This is get assertion */
      result = verifyAuthenticatorAssertionResponse(webauthnResp, [
        result.authrInfo,
      ]);
    } else {
      response.status(400).send({
        status: "failed",
        message: "Can not determine type of response!",
      });
    }

    if (result.verifed) {
      const user = request.user;

      const newAuthnKey = new AuthnKey({
        userId: user._id,
        key: result.authrInfo,
      });

      await newAuthnKey.save();

      response.status(200).send("success");
    } else {
      return response.status(400).send({
        status: "failed",
        message: "Can not authenticate signature!",
      });
    }
  }
);

router.post("/webauthn/login", async (request, response) => {
  const email = request.body.email;
  if (!email)
    return response.status(400).send({ message: "email is requared" });

  const user = await User.findOne({ email });

  if (!user)
    return response.status(400).send({ message: "This user is not exist" });

  const authnKeys = await AuthnKey.find({ userId: user._id });

  if (!authnKeys.length) {
    return response.status(400).send({ message: "you did not yet create key" });
  }

  const _auKeys = authnKeys.map((r) => ({ ...r.key }));

  request.session.id = user._id;
  const getAssertion = generateServerGetAssertion(_auKeys);
  request.session.challenge = getAssertion.challenge;
  response.status(200).send(getAssertion);
});

router.post("/webauthn/login/response", async (request, response) => {
  const data = request.body;
  const userId = request.session.id;

  const authnKeys = await AuthnKey.find({ userId }).exec();

  const _auKeys = authnKeys.map((r) => ({ ...r.key }));

  let clientData = JSON.parse(base64url.decode(data.response.clientDataJSON));

  /* Check challenge... */

  if (clientData.challenge !== request.session.challenge) {
    return response.status(400).send({
      status: "failed",
      message: "Challenges don't match!",
    });
  }
  /* ...and origin */
  if (clientData.origin !== "https://learnwebauthn-vb5r9.ondigitalocean.app") {
    response.status(400).json({
      status: "failed",
      message: "Origins don't match!",
      origin: clientData.origin,
    });
  }

  const result = verifyAuthenticatorAssertionResponse(data, _auKeys);

  if (result.verified) {
    const user = await User.findById(userId);
    request.session.token = jwt.sign(
      {
        _id: user._id,
      },
      process.env.TOKEN_SECRET,
      { expiresIn: 60 * 10 }
    );

    response
      .status(200)
      .send({ id: user._id, email: user.email, isPassword: !!user.password });
  } else {
    return response.status(400).send({ message: "You do not autorize" });
  }
});

router.get("/logout", verify, async (request, response) => {
  request.session.token = null;
  response.end();
});

module.exports = router;
