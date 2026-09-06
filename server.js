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
// Production origins (DamoonCars re-scope, 2026-09-06 — placeholder domains,
// update once the real DamoonCars domain is registered) + localhost for dev.
app.use(cors({credentials: true, origin:[
  'https://xms.damooncars.com',
  'https://api.damooncars.com',
  'http://localhost:3000',            // local dev only
]}));
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

// Port 8256 (DamoonCars re-scope, 2026-09-06 — was 7256) — the reverse proxy
// maps https://auth.damooncars.com onto this local port.
server.listen(8256 , connect =>{
    console.log("server running on port 8256.");
})

