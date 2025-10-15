import { Router } from "express";
import { checkPassword } from "./controller.js";

const passwrouter = Router({ caseSensitive: true });

passwrouter.post("/check", checkPassword);

export default passwrouter;