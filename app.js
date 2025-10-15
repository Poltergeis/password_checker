import express from "express";
import cors from "cors";
import signale from "signale";
import http from "http";

import passwrouter from "./router.js";

const app = express();

app.use(cors());
app.use(express.json());
app.use((req, res, next) => {
    signale.info(`peticion entrante: ${req.method} - ${req.path} - ${req.ip}`);
    next();
});

app.use("/password", passwrouter);

const server = http.createServer(app);

server.listen(9000, "0.0.0.0", () => {
    signale.success("api corriendo en http://localhost:9000");
    signale.info("http://localhost:mi-puerto para acceder desde la misma red");
});