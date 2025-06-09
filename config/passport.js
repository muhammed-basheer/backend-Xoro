import dotenv from 'dotenv';
dotenv.config();

import passport from 'passport';
import GoogleStrategy from 'passport-google-oauth20';
import { Strategy as JwtStrategy, ExtractJwt } from 'passport-jwt';
import User from '../models/User.js';



// JWT Strategy (for protecting routes)
const jwtOptions = {
  jwtFromRequest: (req) => {
    let token = null;
    if (req && req.cookies) {
      token = req.cookies.access_token;
    }
    return token;
  },
  secretOrKey: process.env.JWT_SECRET,
};

passport.use(new JwtStrategy(jwtOptions, async (payload, done) => {
  try {
    const user = await User.findById(payload.id);
    if (user) {
      return done(null, user);
    }
    return done(null, false);
  } catch (error) {
    return done(error, false);
  }
}));

// Google OAuth Strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.NODE_ENV === 'production' 
      ? process.env.PROD_GOOGLE_CALLBACK_URL 
      : process.env.GOOGLE_CALLBACK_URL,
    scope: ['profile', 'email']
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      // console.log('Google Profile:', profile); // For debugging
      
      // Check if user exists with this Google ID
      let user = await User.findOne({ googleId: profile.id });
      
      if (user) {
        // User exists, update last login and return
        user.lastLogin = new Date();
        await user.save();
        return done(null, user);
      }
      
      // Check if user exists with same email but different auth provider
      const existingUser = await User.findOne({ 
        email: profile.emails[0].value,
        authProvider: 'local'
      });
      
      if (existingUser) {
        // Link Google account to existing local account
        existingUser.googleId = profile.id;
        existingUser.authProvider = 'google';
        existingUser.isEmailVerified = true;
        existingUser.lastLogin = new Date();
        existingUser.profilePicture = profile.photos[0]?.value || existingUser.profilePicture;
        await existingUser.save();
        return done(null, existingUser);
      }
      
      // Create new user
      function generateUserId() {
        return 'XORO' + Math.floor(1000000 + Math.random() * 9000000);
      }
      
      const newUser = new User({
        studentId: generateUserId(),
        name: profile.displayName,
        email: profile.emails[0].value,
        googleId: profile.id,
        authProvider: 'google',
        isEmailVerified: true,
        role: 'student',
        profilePicture: profile.photos[0]?.value || "https://img.freepik.com/premium-vector/avatar-profile-icon-flat-style-male-user-profile-vector-illustration-isolated-background-man-profile-sign-business-concept_157943-38764.jpg",
        status: 'active',
        lastLogin: new Date()
      });
      
      await newUser.save();
      // console.log('New Google user created:', newUser.email);
      
      return done(null, newUser);
      
    } catch (error) {
      console.error('Google OAuth Error:', error);
      return done(error, null);
    }
  }
));

// Serialize/Deserialize user (required for sessions, but we're using JWT)
passport.serializeUser((user, done) => {
  done(null, user._id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (error) {
    done(error, null);
  }
});

export default passport;