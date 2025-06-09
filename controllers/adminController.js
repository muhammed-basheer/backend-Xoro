import User from "../models/User.js";

// GET all users
export const getAllUsers = async (req, res) => {
  try {
    const users = await User.find().select("-password -refreshToken");
    
    res.status(200).json(users);
  } catch (err) {
    res.status(500).json({ message: "Error fetching users", error: err });
  }
};

// // PATCH change user role
// export const changeUserRole = async (req, res) => {
//   try {
//     const { id } = req.params;
//     const { role } = req.body;

//     if (!["student", "instructor", "admin"].includes(role)) {
//       return res.status(400).json({ message: "Invalid role" });
//     }

//     const user = await User.findByIdAndUpdate(id, { role }, { new: true });

//     if (!user) return res.status(404).json({ message: "User not found" });

//     res.status(200).json({ message: "Role updated", user });
//   } catch (err) {
//     res.status(500).json({ message: "Error changing role", error: err });
//   }
// };

// // PATCH block/unblock user
// export const blockUser = async (req, res) => {
//   try {
//     const { id } = req.params;

//     const user = await User.findById(id);
//     if (!user) return res.status(404).json({ message: "User not found" });

//     user.isActive = !user.isActive;
//     await user.save();

//     res.status(200).json({ message: `User ${user.isActive ? "unblocked" : "blocked"}`, user });
//   } catch (err) {
//     res.status(500).json({ message: "Error blocking user", error: err });
//   }
// };

// // DELETE user
// export const deleteUser = async (req, res) => {
//   try {
//     const { id } = req.params;

//     const user = await User.findByIdAndDelete(id);
//     if (!user) return res.status(404).json({ message: "User not found" });

//     res.status(200).jso({ message: "User deleted" });
//   } catch (err) {
//     res.status(500).json({ message: "Error deleting user", error: err });
//   }
// };
