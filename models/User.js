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
        profilePicture: { type: String, default: "" }, 

        // STUDENT FIELDS
        enrolledCourses: [{ type: mongoose.Schema.Types.ObjectId, ref: "Course" }], // Courses enrolled

        // INSTRUCTOR FIELDS
        createdCourses: [{ type: mongoose.Schema.Types.ObjectId, ref: "Course" }], // Courses created
        isApprovedInstructor: { type: Boolean, default: false }, // Admin approval required

        isActive: { type: Boolean, default: true }, // Admin can deactivate users
        
    },
    { timestamps: true } 
);

// Hash password before saving to database
userSchema.pre("save", async function (next) {
    if (!this.isModified("password")) return next();
    this.password = await bcrypt.hash(this.password, 10);
    next();
});

module.exports = mongoose.model("User", userSchema);
