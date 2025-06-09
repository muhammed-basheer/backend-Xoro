import mongoose from "mongoose";

const userSchema = new mongoose.Schema(
  {
    studentId: { type: String, required: true, unique: true },
    name: { type: String, required: true },
    email: { type: String, required: true },

    // 🔐 Make password optional for Google users
    password: {
      type: String,
      required: function () {
        return this.authProvider === "local";
      },
    },

    role: {
      type: String,
      enum: ["student", "instructor", "admin"],
      default: "student",
    },

    profilePicture: {
      type: String,
      default:
        "https://img.freepik.com/premium-vector/avatar-profile-icon-flat-style-male-user-profile-vector-illustration-isolated-background-man-profile-sign-business-concept_157943-38764.jpg?semt=ais_hybrid",
    },

    phone: { type: String },
    dateOfBirth: { type: Date },
    gender: {
      type: String,
      enum: ["Male", "Female", "Other", "Prefer-not-to-say"],
    },

    refreshToken: { type: String },
    lastLogin: { type: Date, default: null },

    // 🔁 Google OAuth Fields
    googleId: { type: String, sparse: true },
    authProvider: {
      type: String,
      enum: ["local", "google"],
      default: "local",
    },
    isEmailVerified: { type: Boolean, default: false },

    // 🧑‍🎓 Student fields
    enrolledCourses: [{ type: mongoose.Schema.Types.ObjectId, ref: "Course" }],

    // 👨‍🏫 Instructor fields
    createdCourses: [{ type: mongoose.Schema.Types.ObjectId, ref: "Course" }],
    isApprovedInstructor: { type: Boolean, default: false },

    status: {
      type: String,
      enum: ["active", "inactive", "banned"],
      default: "active",
    },
  },
  { timestamps: true }
);

// ✅ Compound index for email + authProvider uniqueness
userSchema.index({ email: 1, authProvider: 1 }, { unique: true });

export default mongoose.model("User", userSchema);
