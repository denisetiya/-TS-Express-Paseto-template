import express, { Request, Response } from "express";
import url from "./url";
import authenticateToken from "./middleware/paseto.auth";
import response from "./utils/response.api";
import { limiter, blockIPMiddleware } from "./middleware/rete.limiter";



const app = express();

app.use(blockIPMiddleware);

app.use(limiter);

app.use(express.json());

app.use("/v1/", authenticateToken, url);



app.use((req: Request, res: Response) => {
    response(res, 404, "Not Found", "are you developer or hacker ?");
})

app.listen(3000, () => {
    console.log("Server started on port 3000");
});