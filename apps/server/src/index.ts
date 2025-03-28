import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import {CreateUserSchema, SigninSchema} from "@repo/common/types";
import { prismaClient } from "@repo/db/client"

const app = express();
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || "secret"

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

app.listen(3001,()=>{
    console.log('webserver running on port 3001')
})