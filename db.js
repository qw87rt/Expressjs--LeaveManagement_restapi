const mysql = require('mysql');
const connection = mysql.createConnection({
  host: process.env.HOST1,
  user: process.env.DBuser1,
  password: process.env.DBpassword1,
  database: process.env.DBname1,
});

connection.connect((error) => {
  if (error) {
    console.error('Database connection failed: ', error);
  } else {
    console.log('Connected to the database');
  }
});

module.exports = connection;
