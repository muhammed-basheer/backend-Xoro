  // middleware/roleMiddleware.js - Updated with better error handling
  import jwt from "jsonwebtoken";
  import User from "../models/User.js";

  const roleMiddleware = (...allowedRoles) => {
    return async (req, res, next) => {
      try {
        console.log("Checking role middleware...");

        const token = req.cookies.access_token;
        
        if (!token) {
          return res.status(401).json({
            message: "Unauthorized: No token provided",
            redirectTo: determineLoginPage(req)
          });
        }
        
        let decoded;
        try {
          decoded = jwt.verify(token, process.env.JWT_SECRET);
        } catch (error) {
          console.log("Token verification error:", error.message);
          
          // If token is expired and refresh token exists, suggest client to refresh
          if (error.name === 'TokenExpiredError' && req.cookies.refresh_token) {
            return res.status(401).json({
              message: "Token expired",
              tokenExpired: true,
              redirectTo: determineLoginPage(req)
            });
          }
          
          return res.status(401).json({
            message: "Invalid token: " + error.message,
            redirectTo: determineLoginPage(req)
          });
        }
        
        const user = await User.findById(decoded.id);
        
        if (!user) {
          return res.status(404).json({
            message: "User not found",
            redirectTo: determineLoginPage(req)
          });
        }
        
        if (user.status === "banned") {
          return res.status(403).json({
            message: "Account deactivated",
            redirectTo: determineLoginPage(req)
          });
        }
        
        // Check if user role is allowed
        if (!allowedRoles.includes(user.role)) {
          return res.status(403).json({
            message: "Forbidden: Access denied",
            redirectTo: determineDashboardByRole(user.role)
          });
        }
        
        // Attach the user to the request for use in route handlers
        req.user = {
          id: user._id,
          role: user.role,
          email: user.email,
          name: user.name
        };
        console.log("Access granted to role:", req.user.role);

        next();
      } catch (error) {
        console.error("Role middleware error:", error);
        res.status(500).json({
          message: "Server error in authorization",
          redirectTo: determineLoginPage(req)
        });
      }
    };
  };

  // Helper function to determine login page based on request path
  function determineLoginPage(req) {
    const path = req.originalUrl;
    if (path.includes('/admin')) {
      return '/admin/login';
    } else if (path.includes('/instructor')) {
      return '/instructor/login';
    } else {
      return '/login'; // Default to student login
    }
  }

  // Helper function to determine dashboard by role
  function determineDashboardByRole(role) {
    switch (role) {
      case 'admin':
        return '/admin/dashboard';
      case 'instructor':
        return '/instructor/dashboard';
      case 'student':
      default:
        return '/student/dashboard';
    }
  }
  

  export default roleMiddleware;