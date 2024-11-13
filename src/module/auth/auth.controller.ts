import express, { Request, Response } from "express";
import response from "../../utils/response.api";
import admin from "../../config/firbase-admin.conf";
import { 
    generateTokens, 
    createNewUser, 
    cekUser, 
    verifyAccessToken,
    refreshAccessToken 
} from "./auth.service";


const auth: express.Router = express.Router();



// Middleware untuk validasi input
const validateAuthInput = (req: Request, res: Response, next: express.NextFunction) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return response(res, 400, "Bad Request", "Email and password must be filled in");
    }

    // Validasi format email
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return response(res, 400, "Bad Request", "Invalid email format");
    }

    // Validasi password
    if (password.length < 8) {
        return response(res, 400, "Bad Request", "A minimum password of 8 characters");
    }

    next();
};

// Firebase auth route (dikomentari sesuai kode asli)
/*
auth.post("/auth", async(req: Request, res: Response) => {
    const tokenFirebase = req.headers.authorization;

    if (!tokenFirebase) {
        return response(res, 401, "Unauthorized", "Token tidak ditemukan");
    }
    const token = tokenFirebase?.split(" ")[1];
    
    try {
        const user = await admin.auth().verifyIdToken(token as string);
        const tokens = await generateTokens(user.uid, user.email as string);

        return response(res, 200, "Success", null, tokens);

    } catch (error) {
        return response(res, 401, "Unauthorized", error);
    }
});
*/

// Login route dengan rate limiting
auth.post("/login", validateAuthInput, async(req: Request, res: Response) => {
    const { email, password } = req.body;

    try {
        const userAvailable = await cekUser(email, password);

        if (!userAvailable) {
            return response(res, 401, "Unauthorized", "Wrong email or password");
        }

        const tokens = await generateTokens(userAvailable.id, userAvailable.email);

        if (!tokens) {
            return response(res, 401, "Unauthorized", "Failed to make a token");
        }


        // Hanya mengirimkan access token dalam response
        return response(res, 200, "Success", null, tokens);

    } catch (error) {
        console.error('Login error:', error);
        return response(res, 500, "Internal Server Error", "An error occurs when logging in");
    }
});

// Register route
auth.post("/register", validateAuthInput, async (req: Request, res: Response) => {
    const { email, password } = req.body;

    try {
        // Cek apakah email sudah terdaftar
        const existingUser = await cekUser(email, password);
        if (existingUser) {
            return response(res, 409, "Conflict", "Email is registered");
        }

        const user = await createNewUser(email, password);
        if (!user) {
            return response(res, 500, "Internal Server Error", "Failed to make a user");
        }

        const tokens = await generateTokens(user.id, user.email);
        

        // Hanya mengirimkan access token dalam response
        return response(res, 201, "Success", null, tokens);

    } catch (error) {
        console.error('Register error:', error);
        return response(res, 500, "Internal Server Error", "An error occurred during registration");
    }
});

// Route untuk refresh token
auth.post("/refresh-token", async (req: Request, res: Response) => {
    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken) {
        return response(res, 401, "Unauthorized", "Token refresh is not found");
    }

    try {
        const newTokens = await refreshAccessToken(refreshToken);
        
        return response(res, 200, "Success", null, newTokens);

    } catch (error) {
        console.error('Refresh token error:', error);
        return response(res, 401, "Unauthorized", "Refresh token tidak valid");
    }
});

// Route untuk logout
auth.post("/logout", (req: Request, res: Response) => {
    try {
        // res.clearCookie('refreshToken');

        return response(res, 200, "Success", null, "Successfully log out");
    } catch (error) {
        console.error('Logout error:', error);
        return response(res, 500, "Internal Server Error", "An error occurred when loggedout");
    }
});

export default auth;