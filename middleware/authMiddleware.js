import jwt from "jsonwebtoken";
import errorHandling from "../utility/errorHandling.js";

export const verifyAccessToken = (req, res, next) => {
    const token = req.cookies.access_token;

    if (!token) return next(errorHandling(401, "Access token is required"));

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) return next(errorHandling(403, "Invalid access token"));

        req.user = decoded;
        next();
    });
};