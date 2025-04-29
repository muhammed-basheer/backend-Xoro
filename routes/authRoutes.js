import express from "express";
import { signIn, signUp, refreshAccessToken } from "../controllers/authController.js";

const router = express.Router();

router.post('/signup', signUp);
router.post('/signin', signIn);
router.post('/refresh-token', refreshAccessToken); // Add this route for refreshing the access token

export default router;