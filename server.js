const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require('cookie-parser');
const cors = require('cors')
const mongoose = require("mongoose");
const multer  = require('multer')
const upload = multer({ dest: 'public/files' })
const webpush = require('web-push');
const dotenv = require("dotenv");
const crashLogger = require("./utils/crashLogger");
const { patchExpressRouter } = require("./utils/asyncRouteErrors");

patchExpressRouter(express);

//express middlewear
const app = express();
var server = require('http').createServer(app);
// app.use(cors());
// LAN IPs added for phone/device testing (Ethernet 192.168.1.135, Wi-Fi 192.168.1.132) —
// the old 10.185.103.82 entry was a VPN adapter address, unreachable from other devices.
app.use(cors({credentials: true, origin:['http://localhost:3000' , 'https://localhost:3003' , 'http://192.168.1.135:3000', 'http://192.168.1.132:3000']}));
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



app.use((err, req, res, next) => {
    const crashId = crashLogger.logError(err, {
        type: "requestError",
        request: crashLogger.getRequestContext(req)
    });

    console.error(`Request error logged: ${crashId}`, err);

    if (res.headersSent) {
        return next(err);
    }

    return res.status(err.status || 500).json({
        message: "Internal server error",
        crashId
    });
});

process.on("unhandledRejection", (reason) => {
    const crashId = crashLogger.logError(reason, { type: "unhandledRejection" });
    console.error(`Unhandled rejection logged: ${crashId}`, reason);
});

process.on("uncaughtException", (error) => {
    const crashId = crashLogger.logError(error, { type: "uncaughtException" });
    console.error(`Uncaught exception logged: ${crashId}`, error);
});

server.listen(3002 , connect =>{
    console.log("server running on port 3002.");
})

