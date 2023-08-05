require('dotenv').config()

const express = require('express')
const bodyparser = require('body-parser');
const cors = require('cors');
const sql = require("mssql");
const path = require('path');
const port = process.env.PORT || '3000';

var conn = require('./Config/db/sql');
var app = express();

var routes = require('./routes')

app.use(cors());
app.use(bodyparser.json());
app.use(bodyparser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'Public')));
app.use(express.static(path.join(__dirname, 'images')));

app.use('/api',routes)

app.get('/', (req, res) => {
    res.send('Welcome To DiaMarsERP')
})
  
app.listen(port, () => {
  console.log(`listening at http://localhost:${port}`)
})
  