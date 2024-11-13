import { verifyAccessToken } from './../module/auth/auth.service';
import { Request, Response, NextFunction } from 'express';
import response from '../utils/response.api';
import { start } from 'repl';

const authenticateToken = async (req: Request, res: Response, next: NextFunction) => {
    const token = req.headers.authorization?.split(' ')[1];
    const refresh = req.headers['x-refresh-token']

    if (req.path.startsWith("/auth")) {
        return next();
    }

    if (!token) {
        return response(res, 401, "Unauthorized", "Token was not found ");
    }

    try {
    
        const tokenPayload = await verifyAccessToken(token, refresh as string);


        if (!tokenPayload) {
            return response(res, 401, "Unauthorized", "Invalid token");
        }

        next();
    } catch (error: any) {
        console.error("Token validation error:", error);
        
        if (error.message.includes("kadaluarsa")) {
            return response(res, 401, "Unauthorized", "Token has expired");
        }

        return response(res, 401, "Unauthorized", "Invalid token");
    }
};

export default authenticateToken;
