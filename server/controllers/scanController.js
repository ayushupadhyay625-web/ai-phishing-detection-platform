import PhishingScan from "../models/PhishingScan.js";

import {
  analyzeEmailWithML,
  analyzeURLWithML,
} from "../services/mlService.js";


const formatIndicators = (indicators = []) => {
  return indicators.map((item) => ({
    indicator: item.indicator,
    category: item.category || "other",
    weight: item.weight || 0,
  }));
};


// POST /api/scans/email
export const scanEmail = async (req, res) => {
  try {
    const {
      sender = "",
      recipient = "",
      subject = "",
      body = "",
    } = req.body;

    if (!body.trim()) {
      return res.status(400).json({
        success: false,
        message: "Email body is required",
      });
    }

    const detectionResult = await analyzeEmailWithML({
      sender,
      recipient,
      subject,
      body,
    });

    const savedScan = await PhishingScan.create({
      scannedBy: req.user._id,

      scanType: "email",

      emailData: {
        sender,
        recipient,
        subject,
        body,
      },

      extractedUrls:
        detectionResult.extracted_urls || [],

      verdict: detectionResult.verdict,

      riskScore:
  detectionResult.risk_score,

ruleRiskScore:
  detectionResult.rule_risk_score || 0,

mlRiskScore:
  detectionResult.ml_risk_score || 0,

mlAnalysis: {
  available:
    detectionResult.ml_analysis
      ?.available || false,

  prediction:
    detectionResult.ml_analysis
      ?.prediction || "unavailable",

  phishingProbability:
    detectionResult.ml_analysis
      ?.phishing_probability || 0,

  safeProbability:
    detectionResult.ml_analysis
      ?.safe_probability || 0,
},

confidence:
  detectionResult.confidence,

      detectedIndicators: formatIndicators(
        detectionResult.indicators
      ),

      detectionMethod:
        detectionResult.detection_method ||
        "hybrid-explainable-engine-v1",

      status: "completed",
    });

    return res.status(201).json({
      success: true,
      message: "Email analysis completed",
      scan: savedScan,
    });
  } catch (error) {
    console.error("Email scan error:", error);

    return res.status(500).json({
      success: false,
      message:
        error.message ||
        "Email analysis could not be completed",
    });
  }
};


// POST /api/scans/url
export const scanURL = async (req, res) => {
  try {
    const submittedUrl = req.body.url?.trim();

    if (!submittedUrl) {
      return res.status(400).json({
        success: false,
        message: "URL is required",
      });
    }

    const detectionResult = await analyzeURLWithML(
      submittedUrl
    );

    const savedScan = await PhishingScan.create({
      scannedBy: req.user._id,

      scanType: "url",

      submittedUrl,

      verdict: detectionResult.verdict,

      riskScore: detectionResult.risk_score,

      confidence: detectionResult.confidence,

      detectedIndicators: formatIndicators(
        detectionResult.indicators
      ),

      detectionMethod:
        detectionResult.detection_method ||
        "hybrid-explainable-engine-v1",

      status: "completed",
    });

    return res.status(201).json({
      success: true,
      message: "URL analysis completed",
      scan: savedScan,
    });
  } catch (error) {
    console.error("URL scan error:", error);

    return res.status(500).json({
      success: false,
      message:
        error.message ||
        "URL analysis could not be completed",
    });
  }
};


// GET /api/scans/history
export const getScanHistory = async (req, res) => {
  try {
    const page = Math.max(
      Number.parseInt(req.query.page, 10) || 1,
      1
    );

    const limit = Math.min(
      Math.max(
        Number.parseInt(req.query.limit, 10) || 10,
        1
      ),
      50
    );

    const query =
      req.user.role === "admin"
        ? {}
        : {
            scannedBy: req.user._id,
          };

    const totalScans =
      await PhishingScan.countDocuments(query);

    const scans = await PhishingScan.find(query)
      .select("-emailData.body")
      .populate("scannedBy", "name email role")
      .sort({
        createdAt: -1,
      })
      .skip((page - 1) * limit)
      .limit(limit);

    return res.status(200).json({
      success: true,

      pagination: {
        currentPage: page,
        totalPages: Math.ceil(totalScans / limit),
        totalScans,
        resultsPerPage: limit,
      },

      scans,
    });
  } catch (error) {
    console.error("Scan history error:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to retrieve scan history",
    });
  }
};


// GET /api/scans/:scanId
export const getScanById = async (req, res) => {
  try {
    const scan = await PhishingScan.findById(
      req.params.scanId
    ).populate("scannedBy", "name email role");

    if (!scan) {
      return res.status(404).json({
        success: false,
        message: "Scan record not found",
      });
    }

    const isOwner =
      scan.scannedBy._id.toString() ===
      req.user._id.toString();

    const isAdmin = req.user.role === "admin";

    if (!isOwner && !isAdmin) {
      return res.status(403).json({
        success: false,
        message:
          "You cannot access this scan record",
      });
    }

    return res.status(200).json({
      success: true,
      scan,
    });
  } catch (error) {
    console.error("Scan details error:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to retrieve scan details",
    });
  }
};
// PATCH /api/scans/:scanId/feedback
export const submitScanFeedback = async (
  req,
  res
) => {
  try {
    const {
      isCorrect,
      correctedVerdict = null,
      comment = "",
    } = req.body;

    if (typeof isCorrect !== "boolean") {
      return res.status(400).json({
        success: false,
        message:
          "isCorrect must be true or false",
      });
    }

    const allowedVerdicts = [
      "safe",
      "suspicious",
      "phishing",
    ];

    if (
      !isCorrect &&
      !allowedVerdicts.includes(
        correctedVerdict
      )
    ) {
      return res.status(400).json({
        success: false,
        message:
          "A corrected verdict is required",
      });
    }

    const scan = await PhishingScan.findById(
      req.params.scanId
    );

    if (!scan) {
      return res.status(404).json({
        success: false,
        message: "Scan record not found",
      });
    }

    const isOwner =
      scan.scannedBy.toString() ===
      req.user._id.toString();

    const canReview =
      isOwner ||
      req.user.role === "admin" ||
      req.user.role ===
        "security_analyst";

    if (!canReview) {
      return res.status(403).json({
        success: false,
        message:
          "You cannot review this scan",
      });
    }

    scan.analystFeedback = {
      isCorrect,

      correctedVerdict:
        isCorrect
          ? scan.verdict
          : correctedVerdict,

      comment: comment.trim(),

      reviewedBy: req.user._id,

      reviewedAt: new Date(),
    };

    await scan.save();

    return res.status(200).json({
      success: true,
      message:
        "Detection feedback saved",
      analystFeedback:
        scan.analystFeedback,
    });
  } catch (error) {
    console.error(
      "Feedback submission error:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        "Unable to save detection feedback",
    });
  }
};