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

        // ✅ Avoid sending password and refresh token
        const { password: hashedPwd, refreshToken: hiddenToken, ...rest } = newUser._doc;

        // Set secure cookies
        res.cookie("access_token", accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict",
            maxAge: 15 * 60 * 1000
        });

        res.cookie("refresh_token", refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict",
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        res.status(201).json({
            message: "User registered and logged in successfully",
            user: rest
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

        // Save refresh token
        const accessToken = jwt.sign(
            { id: user._id, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: "15m" }
        );

        const refreshToken = jwt.sign(
            { id: user._id },
            process.env.JWT_REFRESH,
            { expiresIn: "7d" }
        );

        user.refreshToken = refreshToken;
        await user.save();

        // Exclude password and refreshToken from response
        const { password: hashedPassword, refreshToken: hiddenToken, ...rest } = user._doc;

        // Set cookies
        res.cookie("access_token", accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict",
            maxAge: 15 * 60 * 1000,
        });

        res.cookie("refresh_token", refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict",
            maxAge: 7 * 24 * 60 * 60 * 1000,
        });

        res.status(200).json({
            message: "User logged in successfully",
            user: rest, 
        });
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
export const logout = async (req, res, next) => {
    try {
        
        const { refresh_token } = req.cookies;
        console.log("Logout refresh token:", refresh_token); // Log the refresh token for debugging

        if (!refresh_token) {
            return res.status(204).send(); // No content, already logged out
        }

        // Find the user by refresh token
        const user = await User.findOne({ refreshToken: refresh_token });
        console.log("User found:", user); // Log the user for debugging

        if (user) {
            user.refreshToken = null; // Clear stored token
            await user.save();
        }

        // Clear cookies
        res.clearCookie('access_token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
        });
        res.clearCookie('refresh_token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
        });

        res.status(200).json({ message: 'Logged out successfully' });
    } catch (error) {
        next(error);
    }
};

