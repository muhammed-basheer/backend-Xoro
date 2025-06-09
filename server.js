// server.js - Add these imports and configurations
import express from "express";
import cookieParser from 'cookie-parser';
import dotenv from "dotenv";
import cors from "cors";
import session from 'express-session'; // Add this
import passport from './config/passport.js'; // Add this
import connectDB from "./config/db.js";
import authRoute from "./routes/authRoutes.js";
import adminRoutes from './routes/adminRoutes.js';
import userRoutes from './routes/userRoutes.js';
import errorMiddleware from "./middleware/errorMiddleware.js";

dotenv.config();
connectDB();

const app = express();

// Configure CORS (your existing configuration is good)
const corsOptions = {
  origin: process.env.CLIENT_URL || 'http://localhost:5173',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept']
};

app.use(cors(corsOptions));

// Session configuration (minimal, since we're using JWT)
app.use(session({
  secret: process.env.JWT_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    maxAge: 15 * 60 * 1000 // 15 minutes
  }
}));

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

app.use(cookieParser());
app.use(express.json());

// Your existing middleware
app.use((req, res, next) => {
  console.log(`${req.method} ${req.url}`);
  next();
});

// Routes (keep your existing routes)
app.use('/api/auth', authRoute);
app.use('/api/admin', adminRoutes);
app.use('/api/users', userRoutes);

// Error handling
app.use(errorMiddleware);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));