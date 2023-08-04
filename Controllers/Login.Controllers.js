const sql = require("mssql");
const jwt = require('jsonwebtoken');
const path = require('path');
var CryptoJS = require("crypto-js");


var { _tokenSecret } = require('../Config/token/TokenConfig.json');

exports.Login = async (req, res) => {
    try {
        var request = new sql.Request();

        request.input('UserId', sql.VarChar, req.body.UserId)
        request = await request.execute('WB_UserLoginAuthentication');
        if (request.recordset) {
            if (request.recordset.length == 1) {
                var bytes = CryptoJS.AES.decrypt(request.recordset[0].Password, process.env.PASS_KEY);
                var originalText = bytes.toString(CryptoJS.enc.Utf8);
                if (originalText == req.body.Password) {
                    if (request.recordset[0].Active == true) {
                        jwt.sign({
                            Emp_Id: request.recordset[0].Emp_Id,
                            UserId: request.recordset[0].UserId,
                            Emp_Name: request.recordset[0].Emp_Name,
                            Emp_Email: request.recordset[0].Emp_Email,
                            Emp_Code: request.recordset[0].Emp_Code,
                            Emp_Department: request.recordset[0].Emp_Department,
                            Emp_Designation: request.recordset[0].Emp_Designation,
                            Active: request.recordset[0].Active,
                            Password: request.recordset[0].Password,
                            Cat: request.recordset[0].Cat,
                        }, _tokenSecret, { expiresIn: "12h" }, (err, token) => {
                            res.json({ Success: 1, Data: token })
                        });
                    } else {
                        res.json({ Success: 4, Data: "User not active" })
                    }
                } else {
                    res.json({ Success: 3, Data: "Password wrong" })
                }

            } else {
                res.json({ Success: 5, Data: "User not found" })
            }


        } else {
            res.json({ Success: 2, Data: "Not Found" })
        }

    } catch (err) {
        res.json({ Success: 0, Data: err })
    }

}