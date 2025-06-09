import express, { Router } from "express";  
import {updateUserProfile } from "../controllers/userController.js";
import roleMiddleware from "../middleware/roleMiddleware.js";

const router = express.Router();

router.use(roleMiddleware('student'))

router.post('/updateProfile',updateUserProfile )

export default router;