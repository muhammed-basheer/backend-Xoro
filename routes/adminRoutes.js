import express from "express";
import {
  getAllUsers,
  // changeUserRole,
  // blockUser,
  // deleteUser,
} from "../controllers/adminController.js";
import roleMiddleware from "../middleware/roleMiddleware.js";

const router = express.Router();

// Protect all admin routes
router.use(roleMiddleware("admin"));

router.get("/users", getAllUsers);
// router.patch("/users/:id/role", changeUserRole);
// router.patch("/users/:id/block", blockUser);
// router.delete("/users/:id", deleteUser);

export default router;
