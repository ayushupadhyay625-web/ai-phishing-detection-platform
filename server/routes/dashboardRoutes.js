import express from "express";

import {
  getDashboardSummary,
  getThreatTrends,
} from "../controllers/dashboardController.js";

import { protect } from "../middleware/authMiddleware.js";


const router = express.Router();


// Every dashboard route requires authentication
router.use(protect);


router.get("/summary", getDashboardSummary);

router.get("/trends", getThreatTrends);


export default router;