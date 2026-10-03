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
// Production origins (launched 2026-07-12) + localhost for development.
// The local entry is port-agnostic: the dev server's port is not fixed (CRA
// moves it when one is taken, and this machine's ephemeral range forced ours
// above 60000), and pinning :3000 here produced silent CORS failures. Mirrors
// isLocalHost() in the frontend's axiosGlobalUrl.js.
const PROD_ORIGINS = [
  'https://xms.lazulitemarble.com',
  'https://api.lazulitemarble.com',
];
const LOCAL_ORIGIN = /^https?:\/\/(localhost|127\.0\.0\.1|192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3})(:\d+)?$/;

app.use(cors({
  credentials: true,
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);           // curl / server-to-server
    if (PROD_ORIGINS.includes(origin) || LOCAL_ORIGIN.test(origin)) return callback(null, true);
    return callback(new Error('Not allowed by CORS'));
  },
}));
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

// Port 7256 (changed from 3002 for the 2026-07-12 launch) — the reverse proxy
// maps https://auth.lazulitemarble.com onto this local port. Configurable via
// PORT so a local machine can run on something else (e.g. 2681, if 7256 is
// already taken locally) without ever touching this committed default —
// production gets 7256 unless its own .env sets PORT, which it shouldn't.
const PORT = process.env.PORT || 7256;
server.listen(PORT , connect =>{
    console.log(`server running on port ${PORT}.`);
})

