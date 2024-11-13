import { V4 } from 'paseto';
import prisma from '../../config/prisma.config';
import bcrypt from 'bcrypt';
import dotenv from 'dotenv';
import { KeyObject, createPrivateKey, createPublicKey, generateKeyPairSync } from 'crypto';
import { platform } from 'os';
dotenv.config();

// Generate Ed25519 keypair jika tidak ada di environment
const generateKeyPair = () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519', {
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem'
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem'
        }
    });
    return { privateKey, publicKey };
};

// Inisialisasi keypair
let privateKey: KeyObject;
let publicKey: KeyObject;

if (process.env.PRIVATE_KEY && process.env.PUBLIC_KEY) {
    try {
        privateKey = createPrivateKey({
            key: process.env.PRIVATE_KEY,  // Langsung gunakan key dari env
            format: 'pem',
            type: 'pkcs8'
        });
        publicKey = createPublicKey({
            key: process.env.PUBLIC_KEY,  // Langsung gunakan key dari env
            format: 'pem',
            type: 'spki'
        });
    } catch (error) {
        console.log("Error loading keys from env, generating new keypair");
        const keys = generateKeyPair();
        privateKey = createPrivateKey(keys.privateKey);
        publicKey = createPublicKey(keys.publicKey);
    }
}


// Interface untuk payload token
interface TokenPayload {
    id: string;
    token?: object;
    email: string;
    exp: string;
    type: 'access' | 'refresh';
}

export const cekUser = async (email: string, password: string) => {
    try {
        const user = await prisma.user.findUnique({ where: { email } });
        if (!user) {
            return null;
        }
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return null;
        }
        return user;
    } catch (error) {
        throw new Error("Error checking user");
    }
}

export const createNewUser = async (email: string, password: string) => {
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const userId = crypto.randomUUID();

        const user = await prisma.user.create({
            data: {
                id: userId,
                email: email,
                password: hashedPassword
            } 
        });
        return user;
    } catch (error) {
        throw new Error("Error creating user");
    }
}

export const generateTokens = async (userId: string, email: string) => {
    try {
        const currentTime = new Date();
        const accessTokenExpiration = new Date(currentTime.getTime() + (15 * 60 * 1000)); // 15 menit
        const refreshTokenExpiration = new Date(currentTime.getTime() + (7 * 24 * 60 * 60 * 1000)); // 7 hari

        // Generate access token
        const accessToken = await V4.sign(
            {
                id: userId,
                email: email,
                exp: accessTokenExpiration.toISOString(), // Menggunakan format ISO string
                type: 'access'
            },
            privateKey
        );

        // Generate refresh token
        const refreshToken = await V4.sign(
            {
                id: userId,
                email: email,
                exp: refreshTokenExpiration.toISOString(), // Menggunakan format ISO string
                type: 'refresh'
            },
            privateKey
        );

        const user = await prisma.user.findUnique({ where: { id: userId } });

        if (!user) {
            throw new Error("User not found");
        }

        return { 
            accessToken, 
            refreshToken,
            expires: {
                access: accessTokenExpiration.toISOString(),
                refresh: refreshTokenExpiration.toISOString()
            }
        };

    } catch (error) {
        console.error("Error generating tokens:", error);
        throw new Error("Error generating tokens");
    }
};

const isTokenExpired = (expirationTime: string): boolean => {
    const expirationDate = new Date(expirationTime); 
    const currentTime = new Date();
    return currentTime >= expirationDate;
};



export const verifyAccessToken = async (token: string, refresh:string): Promise<TokenPayload> => {
   

    try {
        const payload = await V4.verify<TokenPayload>(token, publicKey);


        if (!payload) {
            const payloadRefresh = await V4.verify<TokenPayload>(refresh, publicKey);
            if (!payloadRefresh) {
                throw new Error("Token verification failed");
            }
        
            if (payloadRefresh.type !== 'refresh') {
                throw new Error("Invalid type token type");
            }
        
            if (isTokenExpired(payloadRefresh.exp.toString())) {
                const newTokens = await refreshAccessToken(refresh);
                return {
                    id: payloadRefresh.id,
                    email: payloadRefresh.email,
                    token: {
                        accessToken: newTokens.accessToken,
                        refreshToken: newTokens.refreshToken,
                    },
                    exp: newTokens.expires,
                    type: 'access'
                };
            }
            throw new Error("Refresh token has expired");
        }
        
        if (!payload.exp) {
            throw new Error("Token has no expired information");
        }
        
        if (payload.type !== 'access') {
            throw new Error("Invalid type token type");
        }
        
        return payload;

    } catch (error) {
        if (error instanceof Error) {
            throw new Error(`Verification of Access Tokens Failed: ${error.message}`);
            
        }
        throw new Error("Verification of Access Tokens Failed");
    }
};

export const verifyRefreshToken = async (token: string): Promise<TokenPayload> => {
    try {
        const payload = await V4.verify<TokenPayload>(token, publicKey);
        
        if (!payload.exp) {
            throw new Error("Token has no expired information");
        }

        if (isTokenExpired(payload.exp.toString())) {
            throw new Error("Refresh Token has expired");
        }

        if (payload.type !== 'refresh') {
            throw new Error("Invalid type token type");
        }

        return payload;
    } catch (error) {
        if (error instanceof Error) {
            throw new Error(`Verification of Token Refresh Failure: ${error.message}`);
        }
        throw new Error("Verification of Token Refresh Failed");
    }
};



export const refreshAccessToken = async (refresh: string) => {
    try {
        const payload = await verifyRefreshToken(refresh);
        
        const { accessToken,refreshToken, expires } = await generateTokens(payload.id, payload.email);
        
        return {
            accessToken,
            refreshToken,
            expires: expires.access
        };
    } catch (error) {
        throw new Error("Failed to update the access token");
    }
};