const sql = require("mssql");
const jwt = require('jsonwebtoken');
const path = require('path');
var CryptoJS = require("crypto-js");


var { _tokenSecret } = require('../Config/token/TokenConfig.json');

exports.Login = async (req, res) => {
    try {
        var request = new sql.Request();

        request.input('USERID', sql.VarChar, req.body.UserId)
        request = await request.execute('WB_UserLoginAuthentication');
        if (request.recordset) {
            if (request.recordset.length == 1) {
                var bytes = CryptoJS.AES.decrypt(request.recordset[0].PASSWORD, process.env.PASS_KEY);
                var originalText = bytes.toString(CryptoJS.enc.Utf8);
                if (originalText == req.body.Password) {
                     jwt.sign({
                            USERID: request.recordset[0].USERID
                        }, _tokenSecret, { expiresIn: "12h" }, (err, token) => {
                            res.json({ Success: 1, Data: token })
                        });
                   }else {
                    res.json({ Success: 3, Data: "Password wrong" })
                }

            } else {
                res.json({ Success: 4, Data: "User not found" })
            }


        } else {
            res.json({ Success: 2, Data: "Not Found" })
        }

    } catch (err) {
        res.json({ Success: 0, Data: err })
    }

}