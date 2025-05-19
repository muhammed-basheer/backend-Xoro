// controllers/authController.js - Updated cookie settings
import User from "../models/User.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import errorHandling from "../utility/errorHandling.js";

// Common cookie options for consistency
const getCookieOptions = () => {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: process.env.NODE_ENV === "production" ? "none" : "lax", // Use "none" with secure:true in production to allow cross-site requests
    maxAge: 15 * 60 * 1000, // 15 minutes for access token
    path: "/"  // Important! Ensures cookies are sent with all requests
  };
};

// Refresh token cookie options (longer expiry)
const getRefreshCookieOptions = () => {
  const options = getCookieOptions();
  options.maxAge = 7 * 24 * 60 * 60 * 1000; // 7 days
  return options;
};

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

    function generateUserId() {
      return 'XORO' + Math.floor(1000000 + Math.random() * 9000000);
    }

    const newUser = new User({
      studentId: generateUserId(),
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

    // Set secure cookies with consistent options
    res.cookie("access_token", accessToken, getCookieOptions());
    res.cookie("refresh_token", refreshToken, getRefreshCookieOptions());

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

    if (user.status === 'banned') return next(errorHandling(401, "Your account has been deactivated. Contact support..."));
   
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

    // Set cookies with consistent options
    res.cookie("access_token", accessToken, getCookieOptions());
    res.cookie("refresh_token", refreshToken, getRefreshCookieOptions());

   

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
    const refreshToken = req.cookies.refresh_token;

    if (!refreshToken) return next(errorHandling(401, "Refresh token is required"));

    // Verify the refresh token
    jwt.verify(refreshToken, process.env.JWT_REFRESH, async (err, decoded) => {
      if (err) {
        return next(errorHandling(403, "Invalid refresh token"));
      }

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

      // Generate a new refresh token (token rotation)
      const newRefreshToken = jwt.sign(
        { id: user._id },
        process.env.JWT_REFRESH,
        { expiresIn: "7d" }
      );

      // Update user with new refresh token
      user.refreshToken = newRefreshToken;
      await user.save();

      // Set cookies with new tokens and consistent options
      res.cookie("access_token", accessToken, getCookieOptions());
      res.cookie("refresh_token", newRefreshToken, getRefreshCookieOptions());

      res.status(200).json({ 
        success: true,
        // Optional: include minimal user info that might be needed client-side
        user: {
          id: user._id,
          role: user.role
        }
      });
    });
  } catch (error) {
    console.error("Token refresh error:", error);
    next(error);
  }
};

export const logout = async (req, res, next) => {
  try {
    const refreshToken = req.cookies.refresh_token;

    if (refreshToken) {
      // Find the user by refresh token
      const user = await User.findOne({ refreshToken });
      if (user) {
        user.refreshToken = null; // Clear stored token
        await user.save();
      }
    }

    // Clear cookies - using the same options except maxAge
    const clearOptions = {
      ...getCookieOptions(),
      maxAge: 0
    };
    
    res.clearCookie('access_token', clearOptions);
    res.clearCookie('refresh_token', clearOptions);

    res.status(200).json({ message: 'Logged out successfully' });
  } catch (error) {
    console.error("Logout error:", error);
    next(error);
  }
};

export const adminLogin = async (req, res, next) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user || user.role !== 'admin') {
      return res.status(403).json({ message: 'Access denied: Not an admin' });
    }
    
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });

    const accessToken = jwt.sign(
      { id: user._id, role: user.role }, 
      process.env.JWT_SECRET, 
      { expiresIn: '15m' }
    );
    
    const refreshToken = jwt.sign(
      { id: user._id },
      process.env.JWT_REFRESH,
      { expiresIn: '7d' }
    );
    
    user.refreshToken = refreshToken;
    await user.save();
        console.log("access token", accessToken);
    console.log("refresh token", refreshToken);
        
    // Set cookies with consistent options
    res.cookie("access_token", accessToken, getCookieOptions());
    res.cookie("refresh_token", refreshToken, getRefreshCookieOptions());

    res.status(200).json({ 
      message: 'Admin login successful', 
      user: { 
        id: user._id,
        email: user.email, 
        role: user.role 
      } 
    });
  } catch (error) {
    next(error);
  }
};

export const checkAuth = async (req, res, next) => {
  try {
    const token = req.cookies.access_token;
    
    if (!token) {
      return res.status(401).json({ 
        authenticated: false,
        message: "No access token found"
      });
    }
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);
    
    if (!user) {
      return res.status(404).json({ 
        authenticated: false,
        message: "User not found" 
      });
    }
    
    // Don't send sensitive information
    const { password, refreshToken, ...userData } = user._doc;
    
    res.status(200).json({
      authenticated: true,
      user: userData
    });
  } catch (error) {
    console.error("Auth check error:", error.message);
    
    // If token is expired, suggest a refresh
    if (error.name === 'TokenExpiredError' && req.cookies.refresh_token) {
      return res.status(401).json({ 
        authenticated: false, 
        tokenExpired: true,
        message: "Token expired, please refresh"
      });
    }
    
    res.status(401).json({ 
      authenticated: false,
      message: error.message || "Authentication failed" 
    });
  }
};