import mongoose from "mongoose"
import bcrypt from "bcryptjs"
const userSchema = new mongoose.Schema(
    {
        name: { type: String, required: true },
        email: { type: String, required: true, unique: true },
        password: { type: String, required: true },
        role: { 
            type: String, 
            enum: ["student", "instructor", "admin"], 
            default: "student"  // Default to student
        },
        profilePicture: { type: String, default: "https://img.freepik.com/premium-vector/avatar-profile-icon-flat-style-male-user-profile-vector-illustration-isolated-background-man-profile-sign-business-concept_157943-38764.jpg?semt=ais_hybrid" }, 

        // STUDENT FIELDS
        enrolledCourses: [{ type: mongoose.Schema.Types.ObjectId, ref: "Course" }], // Courses enrolled

        // INSTRUCTOR FIELDS
        createdCourses: [{ type: mongoose.Schema.Types.ObjectId, ref: "Course" }], // Courses created
        isApprovedInstructor: { type: Boolean, default: false }, // Admin approval required

        isActive: { type: Boolean, default: true }, // Admin can deactivate users
        
    },
    { timestamps: true } 
);



export default mongoose.model("User", userSchema);
