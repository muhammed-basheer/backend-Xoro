import User from "../models/User.js"
import bcrypt from "bcryptjs"


export const registerUser = async (req,res)=>{
    try {
        
        const { name , email, password} = req.body; 

        if(!name || !email || !password){
            return res.status(400).json({message : "All fields are required"})
        }
        const existingUser = await User.findOne({email});

        if(existingUser){
            return res.status(400).json({message : "User already exists"})
        }
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password,salt);

        const newUser = new User({
            name,
            email,
            password : hashedPassword,
            role : "student"
        })

        await newUser.save();

        res.status(201).json({message : "User created successfully",newUser})

    } catch (error) {
        console.log(error)
    }
}