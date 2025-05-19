import express from "express";
import cookieParser from 'cookie-parser';
import dotenv from "dotenv"
import cors from "cors"
import connectDB from "./config/db.js";
import authRoute from "./routes/authRoutes.js"
import adminRoutes from './routes/adminRoutes.js';
import errorMiddleware from "./middleware/errorMiddleware.js";

dotenv.config();
connectDB();

const app = express();

// Configure CORS before other middleware
const corsOptions = {
  origin: process.env.CLIENT_URL || 'http://localhost:5173', 
  credentials: true, 
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept']
};

app.use(cors(corsOptions));
app.use(cookieParser());
app.use(express.json());

// Log every request for debugging
app.use((req, res, next) => {
  console.log(`${req.method} ${req.url}`);

  next();
});

// Routes
app.use('/api/auth', authRoute);
app.use('/api/admin', adminRoutes);

// Error handling
app.use(errorMiddleware);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
