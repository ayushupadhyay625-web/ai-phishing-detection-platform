import cors from "cors";
import dotenv from "dotenv";
import express from "express";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import morgan from "morgan";

import connectDB from "./config/db.js";
import authRoutes from "./routes/authRoutes.js";
import dashboardRoutes from "./routes/dashboardRoutes.js";
import scanRoutes from "./routes/scanRoutes.js";

dotenv.config();

await connectDB();

const app = express();
const PORT = process.env.PORT || 5000;

// Render uses a reverse proxy.
app.set("trust proxy", 1);

app.use(helmet());

app.use(
  cors({
    origin: process.env.CLIENT_URL || "http://localhost:5173",
    credentials: true,
  })
);

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));
app.use(morgan("dev"));

// General protection for all API endpoints.
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 200,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: {
    success: false,
    message: "Too many requests. Please try again later.",
  },
});

// Stronger protection against login and registration attacks.
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  message: {
    success: false,
    message: "Too many authentication attempts. Please try again later.",
  },
});

app.use("/api", apiLimiter);
app.use("/api/auth/login", authLimiter);
app.use("/api/auth/register", authLimiter);

app.use("/api/auth", authRoutes);
app.use("/api/scans", scanRoutes);
app.use("/api/dashboard", dashboardRoutes);

app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "Phishing Detection API is running",
  });
});

app.get("/api/health", (req, res) => {
  res.status(200).json({
    success: true,
    status: "healthy",
    service: "Phishing Detection Backend",
    database: "connected",
  });
});
// Return JSON for unknown API routes.
app.use("/api", (req, res) => {
  res.status(404).json({
    success: false,
    message: `API route not found: ${req.method} ${req.originalUrl}`,
  });
});

// Centralized JSON error handler.
app.use((error, req, res, next) => {
  console.error("Unhandled server error:", error);

  res.status(error.status || 500).json({
    success: false,
    message:
      process.env.NODE_ENV === "production"
        ? "An unexpected server error occurred"
        : error.message,
  });
});
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});