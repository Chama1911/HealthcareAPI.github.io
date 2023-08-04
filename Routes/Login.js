var express = require('express');
var router = express.Router();

var { verifyToken } = require('../Config/verify/verify');
var _login = require('../Controllers/Login.Controllers');

router.post('/Login', _login.Login)

module.exports = router;