const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require('cookie-parser');
const cors = require('cors')
const mongoose = require("mongoose");
const multer  = require('multer')
const upload = multer({ dest: 'public/files' })
const webpush = require('web-push');
const dotenv = require("dotenv");
//express middlewear
const app = express();
var server = require('http').createServer(app);
// app.use(cors());
app.use(cors({credentials: true, origin:['http://localhost:3000' , 'http://localhost:3001' , 'http://192.168.1.124:3000']}));
//dotenv middlewear

dotenv.config();
//bodyParser middlewear
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(express.static('public'));
app.use(cookieParser());

//webpush
// webpush.setVapidDetails("mailto:test@test.com" , JSON.stringify(process.env.PublicVapidKey) , JSON.stringify(process.env.PrivateVapidKey));

//routes
app.use('/auth' , require("./routes/users/auth"));



server.listen(3002 , connect =>{
    console.log("server running on port 3002.");
})

