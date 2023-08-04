const sql = require('mssql')

const sql_config = {
    user:process.env.DB_USER,
    password:process.env.DB_PASSWORD,
    server:process.env.DB_SERVER,
    database:process.env.DB_DATABASE,
    options:{
        encrypt:false,
        enableArithAbort: true
    },
    port:parseInt(process.env.DB_PORT),    
}

sql.on('error', err => {
    console.log('SQL ERROR:');
    console.log(err);
})

var conx;
sql.connect(sql_config).then(pool => {
    conx = pool;
});