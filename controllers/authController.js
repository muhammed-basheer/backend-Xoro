// controllers/authController.js - Updated cookie settings
import User from "../models/User.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import errorHandling from "../utility/errorHandling.js";
import passport from 'passport';


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

// controllers/authController.js - Add these Google OAuth methods

// Initiate Google OAuth
export const googleAuth = passport.authenticate('google', {
  scope: ['profile', 'email'],
  prompt: 'select_account' // Always show account selection
});

// Google OAuth Callback
// Google OAuth Callback - Updated with fallback
export const googleCallback = async (req, res, next) => {
  passport.authenticate('google', { session: false }, async (err, user, info) => {
    // console.log('Google OAuth Callback - User:', user);
    
    try {
      if (err) {
        console.error('Google OAuth Error:', err);
        const clientUrl = process.env.CLIENT_URL || 'http://localhost:5173';
        return res.redirect(`${clientUrl}/login?error=oauth_error`);
      }
      
      if (!user) {
        console.error('Google OAuth - No user returned:', info);
        const clientUrl = process.env.CLIENT_URL || 'http://localhost:5173';
        return res.redirect(`${clientUrl}/login?error=oauth_failed`);
      }
      
      // Check if user account is banned
      if (user.status === 'banned') {
        const clientUrl = process.env.CLIENT_URL || 'http://localhost:5173';
        return res.redirect(`${clientUrl}/login?error=account_banned`);
      }
      
      // Generate tokens
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
      
      // Save refresh token
      user.refreshToken = refreshToken;
      await user.save();
      
      // console.log("//////////////////////////",accessToken, refreshToken);
      
      // Set cookies
      res.cookie("access_token", accessToken, getCookieOptions());
      res.cookie("refresh_token", refreshToken, getRefreshCookieOptions());
      
      // Redirect to frontend with success - with fallback URL
      const clientUrl = process.env.CLIENT_URL || 'http://localhost:5173';
      console.log('Redirecting to:', `${clientUrl}?login=success`);
      res.redirect(`${clientUrl}?login=success`);
      
    } catch (error) {
      console.error('Google OAuth Callback Error:', error);
      const clientUrl = process.env.CLIENT_URL || 'http://localhost:5173';
      res.redirect(`${clientUrl}/login?error=server_error`);
    }
  })(req, res, next);
};

// Link Google account to existing user
export const linkGoogleAccount = async (req, res, next) => {
  try {
    const userId = req.user.id; // From JWT middleware
    const { googleToken } = req.body;
    
    if (!googleToken) {
      return res.status(400).json({ message: 'Google token is required' });
    }
    
    // Verify Google token
    const { OAuth2Client } = require('google-auth-library');
    const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
    
    const ticket = await client.verifyIdToken({
      idToken: googleToken,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    
    const payload = ticket.getPayload();
    const googleId = payload.sub;
    const email = payload.email;
    
    // Check if Google account is already linked to another user
    const existingGoogleUser = await User.findOne({ googleId });
    if (existingGoogleUser && existingGoogleUser._id.toString() !== userId) {
      return res.status(400).json({ 
        message: 'This Google account is already linked to another user' 
      });
    }
    
    // Update current user
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    // Verify email matches
    if (user.email !== email) {
      return res.status(400).json({ 
        message: 'Google account email does not match your account email' 
      });
    }
    
    user.googleId = googleId;
    user.isEmailVerified = true;
    await user.save();
    
    res.status(200).json({ 
      message: 'Google account linked successfully',
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        isEmailVerified: user.isEmailVerified
      }
    });
    
  } catch (error) {
    console.error('Link Google Account Error:', error);
    next(error);
  }
};

// Unlink Google account
export const unlinkGoogleAccount = async (req, res, next) => {
  try {
    const userId = req.user.id;
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    // Ensure user has a password before unlinking
    if (!user.password && user.authProvider === 'google') {
      return res.status(400).json({ 
        message: 'Please set a password before unlinking your Google account' 
      });
    }
    
    user.googleId = undefined;
    user.authProvider = 'local';
    await user.save();
    
    res.status(200).json({ message: 'Google account unlinked successfully' });
    
  } catch (error) {
    console.error('Unlink Google Account Error:', error);
    next(error);
  }
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
    // console.log("Checking auth with token:", token);
    
    
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