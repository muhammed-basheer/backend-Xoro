import express from "express";
import cookieParser from 'cookie-parser';
import dotenv from "dotenv"
import cors from "cors"
import connectDB from "./config/db.js";
import authRoute from "./routes/authRoutes.js"

dotenv.config();
connectDB();

const app = express();
app.use(cookieParser());
app.use(express.json());
app.use(cors({
    origin: 'http://localhost:5173', // your frontend URL
    credentials: true // allow cookies, authorization headers
}));

app.use('/api/auth',authRoute)


const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
