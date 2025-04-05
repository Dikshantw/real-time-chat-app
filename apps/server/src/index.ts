import express, { Request } from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import {CreateRoomSchema, CreateUserSchema, SigninSchema} from "@repo/common/types";
import { prismaClient } from "@repo/db/client"
import { middleware } from "./middleware";

const app = express();
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || "secret"

interface AuthenticatedRequest extends Request {
    userId?: string
}

app.post('/signup', async (req,res) => {
    const parsedData = CreateUserSchema.safeParse(req.body);
    if(!parsedData.success){
        console.log(parsedData.error);
        res.status(400).json({message: "Incorrect Inputs"})
        return
    }
    try {
        const hashedPassword = await bcrypt.hash(parsedData.data.password, 10)
        const user = await prismaClient.user.create({
            data: {
                email: parsedData.data.email,
                password: hashedPassword,
                name: parsedData.data.username
            }
        })
        res.status(201).json({userId: user.id})
    } catch (error) {
        res.status(409).json({message: "User already exists with this username"});
    }
})

app.post('/signin', async(req,res) => {
    const parsedData = SigninSchema.safeParse(req.body);
    if(!parsedData.success){
        res.status(400).json({message: "Incorrect Inputs"});
        return
    }
    const user = await prismaClient.user.findFirst({
        where: {
            email: parsedData.data.email
        }
    })
    if(!user || !(await bcrypt.compare(parsedData.data.password, user.password))){
        res.status(401).json({message: "Invalid Credentials"});
        return;
    }

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: "7d" });
    
    res.json({token})
    
})

app.post('/room', middleware, async(req:AuthenticatedRequest,res) => {
    const parsedData = CreateRoomSchema.safeParse(req.body);
    if(!parsedData.success){
        res.status(400).json({message: "Invalid Inputs"})
        return
    }

    const userId = req.userId
    if(!userId){
        res.status(401).json({message: "Unauthorized"});
        return
    }
    try {
        const room = await prismaClient.room.create({
            data: {slug: parsedData.data.name , adminId: userId}
        })
        res.status(201).json({roomId: room.id})
    } catch (error) {
        res.status(400).json({message: "Room already exists with this name"})
    }
})

app.get('/chat/:roomId', async (req,res)=>{

    try {
        const roomId = Number(req.params.roomId);
        if(isNaN(roomId)){
            res.status(400).json({message: "Invalid Room ID"})
        }
    const messages = await prismaClient.chat.findMany({
        where:{roomId: roomId},
        orderBy: {id :"desc"},
        take: 1000
    })

    res.json({messages})    
    } catch (error) {
        console.error(error);
        res.status(500).json({message: "Internal Server Error"})
    }
    
})

app.listen(3001,()=>{
    console.log('webserver running on port 3001')
})