import User from "../models/User.js"
import bcrypt from "bcryptjs"
import jwt from "jsonwebtoken"
import errorHandling from "../utility/errorHandling.js"


export const signUp = async (req, res, next) => {
    try {
        const { name, email, password } = req.body;
        if (!name || !email || !password) {
            return res.status(400).json({ message: "All fields are required" });
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: "User already exists" });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = new User({
            name,
            email,
            password: hashedPassword,
            role: "student"
        });

        await newUser.save();

        // ✅ Auto-login logic after registration
        const { password: hashedPwd, ...rest } = newUser._doc;

        const accessToken = jwt.sign(
            { id: newUser._id, role: newUser.role },
            process.env.JWT_SECRET,
            { expiresIn: "15m" }
        );

        const refreshToken = jwt.sign(
            { id: newUser._id },
            process.env.JWT_REFRESH,
            { expiresIn: "7d" }
        );

        newUser.refreshToken = refreshToken;
        await newUser.save();

        res.cookie("access_token", accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict",
            maxAge: 15 * 60 * 1000, // 15 minutes
        });

        res.cookie("refresh_token", refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict",
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        });

        res.status(201).json({
            message: "User registered and logged in successfully",
            user: rest,
            accessToken
        });

    } catch (error) {
        next(error);
    }
};


export const signIn = async (req, res, next) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) return next(errorHandling(400, "All fields are required"));

        const user = await User.findOne({ email });
        if (!user) return next(errorHandling(401, "Invalid email...!"));

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return next(errorHandling(401, "Invalid Password...!"));

        if (!user.isActive) return next(errorHandling(401, "Your account has been deactivated. Contact support..."));

        const { password: hashedPassword, ...rest } = user._doc;

        // Generate Access Token
        const accessToken = jwt.sign(
            { id: user._id, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: "15m" } // Short-lived access token
        );
        console.log("JWT_SECRET:", process.env.JWT_SECRET);
        
        // Generate Refresh Token
        const refreshToken = jwt.sign(
            { id: user._id },
            process.env.JWT_REFRESH,
            
            { expiresIn: "7d" } // Long-lived refresh token
        );  
        
        console.log("JWT_REFRESH:", process.env.JWT_REFRESH);
        // Save refresh token in the database (optional, for better security)
        user.refreshToken = refreshToken;
        await user.save();  

        // Set tokens in cookies
        res.cookie("access_token", accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict",
            maxAge: 15 * 60 * 1000, // 15 minutes
        });

        res.cookie("refresh_token", refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict",
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        });

        res.status(200).json({ message: true, user: rest, accessToken });
    } catch (error) {
        next(error);
    }
};
export const refreshAccessToken = async (req, res, next) => {
    try {
        const { refreshToken } = req.cookies;

        if (!refreshToken) return next(errorHandling(401, "Refresh token is required"));

        // Verify the refresh token
        jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET, async (err, decoded) => {
            if (err) return next(errorHandling(403, "Invalid refresh token"));

            const user = await User.findById(decoded.id);
            if (!user || user.refreshToken !== refreshToken) {
                return next(errorHandling(403, "Invalid refresh token"));
            }

            // Generate a new access token
            const accessToken = jwt.sign(
                { id: user._id, role: user.role },
                process.env.JWT_SECRET,
                { expiresIn: "15m" }
            );

            res.cookie("access_token", accessToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === "production",
                sameSite: "strict",
                maxAge: 15 * 60 * 1000, // 15 minutes
            });

            res.status(200).json({ accessToken });
        });
    } catch (error) {
        next(error);
    }
};