require('dotenv').config();
const mysql = require('mysql2');

const db = mysql.createConnection({
    host:process.env.HOST,
    user:process.env.USER,
    password:process.env.PASSWORD,
    database:process.env.DATABASE
});

db.connect((err) =>{ 
    if(err){
        err.status(500).json('Failed to connect to database' , err.stack);
    }

    console.log('connected to server');
});

module.exports = db;
