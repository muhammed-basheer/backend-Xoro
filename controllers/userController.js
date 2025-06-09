import User from "../models/User.js";

export const updateUserProfile = async (req, res) => {
    try {
        const { name, phone, gender, dateOfBirth } = req.body;
        
        const updateData = { name, phone, gender };
        
        if (dateOfBirth) {
            const date = new Date(dateOfBirth);
            date.setUTCHours(0, 0, 0, 0);
            updateData.dateOfBirth = date;
        }
        
        const user = await User.findByIdAndUpdate(
            req.user.id, 
            { $set: updateData }, 
            { new: true, runValidators: true }
        );
        
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }
        
        const responseUser = {
            ...user.toObject(),
            dateOfBirth: user.dateOfBirth ? 
                `${String(user.dateOfBirth.getUTCDate()).padStart(2, '0')}-${String(user.dateOfBirth.getUTCMonth() + 1).padStart(2, '0')}-${user.dateOfBirth.getUTCFullYear()}` : null
        };
        
        res.status(200).json({
            success: true,
            message: "Profile updated successfully",
            user: responseUser
        });
        
    } catch (error) {
        console.error("Profile update failed:", error);
        res.status(500).json({ 
            success: false,
            message: "Server error. Could not update profile."
        });
    }
}