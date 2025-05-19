import express from "express";
import { signIn, signUp, refreshAccessToken, logout,adminLogin, checkAuth} from "../controllers/authController.js";

const router = express.Router();
// user authentication routes
router.post('/signup', signUp);
router.post('/signin', signIn);
router.post('/refresh-token', refreshAccessToken); 
router.post('/logout', logout);


// admin authentication routes
router.post('/admin-login', adminLogin);   

router.get('/check-auth', checkAuth);

export default router;