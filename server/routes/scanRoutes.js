import express from "express";

import {
  getScanById,
  getScanHistory,
  scanEmail,
  scanURL,
  submitScanFeedback,
} from "../controllers/scanController.js";

import {
  protect,
} from "../middleware/authMiddleware.js";


const router = express.Router();


// Protect every scan route
router.use(protect);


// Scan routes
router.post("/email", scanEmail);
router.post("/url", scanURL);


// History route
router.get("/history", getScanHistory);


// Feedback route
router.patch(
  "/:scanId/feedback",
  submitScanFeedback
);


// Individual scan route
router.get("/:scanId", getScanById);


export default router;