const jwt = require("jsonwebtoken");

module.exports = function (req, res, next) {
    const token = request.session.token
    if (!token) return res.status(401).send({message: 'Access Denied'});

    try {
        req.user = jwt.verify(token, process.env.TOKEN_SECRET);
        next();
    } catch (e) {
        //console.log(e)
        res.status(401).send(e)
    }
}