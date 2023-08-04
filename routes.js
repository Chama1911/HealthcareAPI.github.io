var express = require('express');
var router = express.Router();

var Login = require('./Routes/Login')


router.use('/Login', Login);


module.exports = router;