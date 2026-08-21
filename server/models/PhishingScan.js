import mongoose from "mongoose";

const phishingScanSchema = new mongoose.Schema(
  {
    scannedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },

    scanType: {
      type: String,
      enum: ["email", "url"],
      required: true,
    },

    emailData: {
      sender: {
        type: String,
        trim: true,
        default: "",
      },

      recipient: {
        type: String,
        trim: true,
        default: "",
      },

      subject: {
        type: String,
        trim: true,
        default: "",
      },

      body: {
        type: String,
        default: "",
      },
    },

    submittedUrl: {
      type: String,
      trim: true,
      default: "",
    },

    extractedUrls: [
      {
        type: String,
        trim: true,
      },
    ],

    verdict: {
      type: String,
      enum: ["safe", "suspicious", "phishing"],
      required: true,
    },

    riskScore: {
      type: Number,
      required: true,
      min: 0,
      max: 100,
    },
ruleRiskScore: {
  type: Number,
  min: 0,
  max: 100,
  default: 0,
},

mlRiskScore: {
  type: Number,
  min: 0,
  max: 100,
  default: 0,
},

mlAnalysis: {
  available: {
    type: Boolean,
    default: false,
  },

  prediction: {
    type: String,
    enum: [
      "safe",
      "phishing",
      "unavailable",
    ],
    default: "unavailable",
  },

  phishingProbability: {
    type: Number,
    min: 0,
    max: 100,
    default: 0,
  },

  safeProbability: {
    type: Number,
    min: 0,
    max: 100,
    default: 0,
  },
},
    confidence: {
      type: Number,
      min: 0,
      max: 100,
      default: 0,
    },

    detectedIndicators: [
      {
        indicator: {
          type: String,
          required: true,
        },

        category: {
          type: String,
          enum: [
            "content",
            "url",
            "sender",
            "urgency",
            "credential_request",
            "formatting",
            "other",
          ],
          default: "other",
        },

        weight: {
          type: Number,
          default: 0,
        },
      },
    ],

    detectionMethod: {
      type: String,
      default: "hybrid-rule-engine-v1",
    },

    status: {
      type: String,
      enum: ["completed", "failed"],
      default: "completed",
    },
    analystFeedback: {
  isCorrect: {
    type: Boolean,
    default: null,
  },

  correctedVerdict: {
    type: String,
    enum: [
      "safe",
      "suspicious",
      "phishing",
      null,
    ],
    default: null,
  },

  comment: {
    type: String,
    trim: true,
    maxlength: 500,
    default: "",
  },

  reviewedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    default: null,
  },

  reviewedAt: {
    type: Date,
    default: null,
  },
},
  },
  {
    timestamps: true,
  }
);

phishingScanSchema.index({
  scannedBy: 1,
  createdAt: -1,
});

phishingScanSchema.index({
  verdict: 1,
  createdAt: -1,
});

const PhishingScan = mongoose.model(
  "PhishingScan",
  phishingScanSchema
);

export default PhishingScan;