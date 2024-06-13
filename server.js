require('dotenv').config()
const express = require('express');
const bodyParser = require('body-parser'); 
const cors = require('cors');
const clientside = require('./routes/clientside');
const adminside = require('./routes/adminside');


const app = express();
app.use(
    cors({
      origin: "*",
      credentials: true,
      allowedHeaders: ["Content-Type", "Authorization"],
    })
  );



app.use(express.json());


app.use('/clientside', clientside);
app.use('/adminside', adminside);


const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`API server is running on port ${port}`);
});
