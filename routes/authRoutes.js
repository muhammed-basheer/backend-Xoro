// routes/authRoutes.js - Add these routes
import express from 'express';
import { 
  signUp, 
  signIn, 
  logout, 
  refreshAccessToken, 
  adminLogin, 
  checkAuth,
  googleAuth,           // Add this
  googleCallback,       // Add this
  linkGoogleAccount,    // Add this
  unlinkGoogleAccount   // Add this
} from '../controllers/authController.js';
import roleMiddleware from "../middleware/roleMiddleware.js";

const router = express.Router();

// Existing routes
router.post('/signup', signUp);
router.post('/signin', signIn);
router.post('/logout', logout);
router.post('/refresh', refreshAccessToken);
router.post('/admin-login', adminLogin);
router.get('/check', checkAuth);

// Google OAuth routes
router.get('/google', googleAuth);
router.get('/google/callback', googleCallback);

// Account linking routes (protected)
router.post('/link-google', roleMiddleware(), linkGoogleAccount);
router.post('/unlink-google', roleMiddleware(), unlinkGoogleAccount);
export default router;