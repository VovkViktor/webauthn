const jwt = require("jsonwebtoken");

module.exports = function (req, res, next) {
  console.log(req.headers.authorization.split(" ")[1]);

  const _bearer = req.headers.authorization || "";

  const token = req.session.token || _bearer.split(" ")[1];

  if (!token) return res.status(401).send({ message: "Access Denied" });

  try {
    req.user = jwt.verify(token, process.env.TOKEN_SECRET);
    next();
  } catch (e) {
    //console.log(e)
    res.status(401).send(e);
  }
};
