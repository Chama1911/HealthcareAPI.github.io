var nodemailer = require('nodemailer');

var transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_PWD
    }
});



function sendSingle(mailOptions)    {
    return new Promise(function (resolve, reject) {
        return transporter.sendMail(mailOptions, function(error, info){
            if (error) {
                resolve(false);
            } else {
                resolve(true);
            }
        });
    });
}

function sendAttachment(mailOptions,attachUrl) {
    return new Promise(function (resolve, reject) {
        return transporter.sendMail(mailOptions, function(error, info){
            if (error) {
                resolve(false);
            } else {
                resolve(true);
            }
        });
    });
}


function sendHtml(email,HtmlPath,templateData,subject)    {
    return new Promise(function (resolve, reject) {


        var path = require('path');
        var fs = require('fs');
        var handlebars = require('handlebars');



        return fs.readFile(HtmlPath, {encoding: 'utf-8'}, function (err, html) {
            if(!err){
                var template = handlebars.compile(html);
                var result = template(templateData);

                var mailOptions = { from: process.env.GMAIL_USER, to: email, subject: subject, html: result};
                // var mailOptions = { from: process.env.GMAIL_USER, to: '111111111', subject: subject, html: result};

                return transporter.sendMail(mailOptions, function(error, info){
                    if (error) {
                        resolve(false);
                    } else {
                        resolve(true);
                    }
                });
            }else{
                resolve(false);
            }
        });
    });
}

module.exports = {sendSingle, sendAttachment,sendHtml};