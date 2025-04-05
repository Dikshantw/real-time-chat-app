import { NextFunction, Request, Response } from 'express';
import jwt from 'jsonwebtoken'

const JWT_SECRET = process.env.JWT_SECRET || "secret"

interface AuthenticatedRequest extends Request {
    userId?: string
}

export function middleware(req:AuthenticatedRequest,res: Response,next: NextFunction){
    try {
        const authHeader = req.header("authorization");
        if(!authHeader){
            res.status(401).json({message: "Unauthorized: No token Provided"});
            return
        }
        const decoded = jwt.verify(authHeader,JWT_SECRET) as {userId: string};
        req.userId = decoded.userId
        next();
    } catch (error) {
        res.status(403).json({message: "Unauthorized: Invalid Token"})
    }

}