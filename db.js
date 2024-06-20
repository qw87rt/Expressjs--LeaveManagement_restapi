const mysql = require('mysql');
const connection = mysql.createConnection({
  host: process.env.HOST,
  user: process.env.DBuser,
  password: process.env.DBpassword,
  database: process.env.DBname,
});

connection.connect((error) => {
  if (error) {
    console.error('Database connection failed: ', error);
  } else {
    console.log('Connected to the database');
  }
});

module.exports = connection;
