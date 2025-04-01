import User from "../models/User.js"
import bcrypt from "bcryptjs"
import jwt from "jsonwebtoken"
import errorHandling from "../utility/errorHandling.js"


export const signUp = async (req, res, next)=>{
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
        next(error)
    }
}

export const signIn = async(req, res, next)=>{
    try {

        const {email, password} = req.body;

        if(!email || !password) return next(errorHandling(400, "All fields are required"))

        const user = await User.findOne({email});
        if(!user) return next(errorHandling(401, "Invalid email...!"))

        const isMatch = await bcrypt.compare(password, user.password);
        if(!isMatch) return next (errorHandling(401, "Invalid  Password...!"))

        if(!user.isActive) return next(errorHandling(401, "Your account has been deactivated. contact support..."))

        const {password : hashedPassword, ...rest} = user._doc

        const token = jwt.sign(
            {id : user._id, role : user.role},
            process.env.JWT_SECRET,
            {expiresIn : "7d"}
        )

        res.cookie("access_token",token, {
            httpOnly : true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict",
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        })
        res.status(200).json({ message : true, user : rest, token })
        
    } catch (error) {
        next(error)
    }
}