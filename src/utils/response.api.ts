import { Response } from "express";

const response = (
    res: Response,
    status: number,
    message: string,
    error: any = null,
    content: any = null,
    meta: any = null,
) => {

    if (res.locals.newTokens) {
        meta.token = res.locals.newTokens;
    }

    res.status(status).json({
        statusCode: status,
        message,
        ...(error && { error }), 
        ...(content && { content }),
        ...(meta && { meta }),
    });
};

export default response;
