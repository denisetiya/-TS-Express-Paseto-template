import express from "express";
import auth from "./module/auth/auth.controller";

const url: express.Router = express();

url.use("/auth", auth);

export default url