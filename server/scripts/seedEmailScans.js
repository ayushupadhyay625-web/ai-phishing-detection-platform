import dotenv from "dotenv";
import fs from "node:fs";
import path from "node:path";
import {
  fileURLToPath,
} from "node:url";

import {
  parse,
} from "csv-parse/sync";

import connectDB from "../config/db.js";
import PhishingScan from "../models/PhishingScan.js";
import User from "../models/User.js";


dotenv.config();


const currentFilePath =
  fileURLToPath(import.meta.url);

const currentDirectory =
  path.dirname(currentFilePath);

const serverDirectory =
  path.resolve(
    currentDirectory,
    ".."
  );

const projectDirectory =
  path.resolve(
    serverDirectory,
    ".."
  );

const datasetPath =
  path.join(
    projectDirectory,
    "ml-service",
    "data",
    "phishing_emails_1000.csv"
  );

const SEED_METHOD =
  "synthetic-email-dataset-seed-v1";


const phishingIndicators = [
  {
    indicator:
      "Suspicious urgency and account-verification language detected",
    category: "urgency",
    weight: 22,
  },
  {
    indicator:
      "Email requests credentials or sensitive account information",
    category: "credential_request",
    weight: 28,
  },
  {
    indicator:
      "Suspicious sender domain pattern detected",
    category: "sender",
    weight: 15,
  },
  {
    indicator:
      "Insecure or suspicious embedded URL detected",
    category: "url",
    weight: 20,
  },
  {
    indicator:
      "Machine-learning model detected phishing language",
    category: "other",
    weight: 15,
  },
];


const safeIndicators = [
  {
    indicator:
      "No common phishing language patterns detected",
    category: "content",
    weight: 0,
  },
  {
    indicator:
      "Machine-learning model classified the message as legitimate",
    category: "other",
    weight: 0,
  },
];


const randomInteger = (
  minimum,
  maximum
) => {
  return Math.floor(
    Math.random() *
      (maximum - minimum + 1)
  ) + minimum;
};


const getRandomDate = () => {
  const now = new Date();

  const daysAgo =
    randomInteger(0, 179);

  const hoursAgo =
    randomInteger(0, 23);

  const minutesAgo =
    randomInteger(0, 59);

  const generatedDate =
    new Date(now);

  generatedDate.setDate(
    generatedDate.getDate() - daysAgo
  );

  generatedDate.setHours(
    generatedDate.getHours() - hoursAgo
  );

  generatedDate.setMinutes(
    generatedDate.getMinutes() -
      minutesAgo
  );

  return generatedDate;
};


const extractURLs = (text) => {
  const urlPattern =
    /https?:\/\/[^\s<>"')]+/gi;

  return text.match(urlPattern) || [];
};


const selectIndicators = (
  indicatorCollection,
  minimum,
  maximum
) => {
  const shuffledIndicators = [
    ...indicatorCollection,
  ].sort(() => Math.random() - 0.5);

  const indicatorCount =
    randomInteger(
      minimum,
      Math.min(
        maximum,
        shuffledIndicators.length
      )
    );

  return shuffledIndicators.slice(
    0,
    indicatorCount
  );
};


const findSeedUser = async () => {
  const requestedEmail =
    process.env.SEED_USER_EMAIL
      ?.trim()
      .toLowerCase();

  if (requestedEmail) {
    const selectedUser =
      await User.findOne({
        email: requestedEmail,
      });

    if (!selectedUser) {
      throw new Error(
        "No user was found for "
        + `SEED_USER_EMAIL=${requestedEmail}`
      );
    }

    return selectedUser;
  }

  const adminUser =
    await User.findOne({
      role: "admin",
      isActive: true,
    }).sort({
      createdAt: 1,
    });

  if (adminUser) {
    return adminUser;
  }

  const firstActiveUser =
    await User.findOne({
      isActive: true,
    }).sort({
      createdAt: 1,
    });

  if (!firstActiveUser) {
    throw new Error(
      "No active user exists. Register "
      + "an account before running the seed."
    );
  }

  return firstActiveUser;
};


const createPhishingScan = (
  record,
  user,
  createdAt
) => {
  const riskScore =
    randomInteger(72, 98);

  const mlRiskScore =
    randomInteger(74, 97);

  const ruleRiskScore =
    randomInteger(70, 100);

  const confidence =
    randomInteger(82, 98);

  const emailText =
    `${record.subject} ${record.body}`;

  const extractedURLs =
    extractURLs(emailText);

  return {
    scannedBy: user._id,
    scanType: "email",

    emailData: {
      sender: record.sender,
      recipient: user.email,
      subject: record.subject,
      body: record.body,
    },

    submittedUrl: "",
    extractedUrls: extractedURLs,

    verdict: "phishing",
    riskScore,
    ruleRiskScore,
    mlRiskScore,

    mlAnalysis: {
      available: true,
      prediction: "phishing",
      phishingProbability:
        mlRiskScore,
      safeProbability:
        100 - mlRiskScore,
    },

    confidence,

    detectedIndicators:
      selectIndicators(
        phishingIndicators,
        3,
        5
      ),

    detectionMethod: SEED_METHOD,
    status: "completed",

    analystFeedback: {
      isCorrect: null,
      correctedVerdict: null,
      comment: "",
      reviewedBy: null,
      reviewedAt: null,
    },

    createdAt,
    updatedAt: createdAt,
  };
};


const createSafeScan = (
  record,
  user,
  createdAt
) => {
  const riskScore =
    randomInteger(4, 28);

  const mlRiskScore =
    randomInteger(3, 25);

  const ruleRiskScore =
    randomInteger(0, 24);

  const confidence =
    randomInteger(79, 97);

  return {
    scannedBy: user._id,
    scanType: "email",

    emailData: {
      sender: record.sender,
      recipient: user.email,
      subject: record.subject,
      body: record.body,
    },

    submittedUrl: "",
    extractedUrls: [],

    verdict: "safe",
    riskScore,
    ruleRiskScore,
    mlRiskScore,

    mlAnalysis: {
      available: true,
      prediction: "safe",
      phishingProbability:
        mlRiskScore,
      safeProbability:
        100 - mlRiskScore,
    },

    confidence,

    detectedIndicators:
      selectIndicators(
        safeIndicators,
        1,
        2
      ),

    detectionMethod: SEED_METHOD,
    status: "completed",

    analystFeedback: {
      isCorrect: null,
      correctedVerdict: null,
      comment: "",
      reviewedBy: null,
      reviewedAt: null,
    },

    createdAt,
    updatedAt: createdAt,
  };
};


const loadDataset = () => {
  if (!fs.existsSync(datasetPath)) {
    throw new Error(
      "Dataset not found at: "
      + datasetPath
    );
  }

  const csvContent =
    fs.readFileSync(
      datasetPath,
      "utf-8"
    );

  const records = parse(
    csvContent,
    {
      columns: true,
      skip_empty_lines: true,
      trim: true,
    }
  );

  if (records.length !== 1000) {
    console.warn(
      "Warning: expected 1000 records "
      + `but found ${records.length}.`
    );
  }

  return records;
};


const seedEmailScans = async () => {
  try {
    await connectDB();

    console.log(
      "\nLoading email dataset..."
    );

    const records = loadDataset();

    const user =
      await findSeedUser();

    console.log(
      `Assigning records to: ${user.email}`
    );

    /*
     * This removes only records previously
     * generated by this exact seed script.
     * Genuine scans are not removed.
     */
    const previousSeedResult =
      await PhishingScan.deleteMany({
        scannedBy: user._id,
        detectionMethod: SEED_METHOD,
      });

    console.log(
      "Previous generated records removed: "
      + previousSeedResult.deletedCount
    );

    const scanDocuments =
      records.map((record) => {
        const createdAt =
          getRandomDate();

        if (
          record.label
            ?.trim()
            .toLowerCase() ===
          "phishing"
        ) {
          return createPhishingScan(
            record,
            user,
            createdAt
          );
        }

        return createSafeScan(
          record,
          user,
          createdAt
        );
      });

    console.log(
      "Inserting records into MongoDB..."
    );

    const insertedScans =
      await PhishingScan.insertMany(
        scanDocuments,
        {
          ordered: false,
        }
      );

    const phishingCount =
      insertedScans.filter(
        (scan) =>
          scan.verdict === "phishing"
      ).length;

    const safeCount =
      insertedScans.filter(
        (scan) =>
          scan.verdict === "safe"
      ).length;

    console.log("\n" + "=".repeat(60));
    console.log(
      "MONGODB SEED COMPLETED"
    );
    console.log("=".repeat(60));

    console.log(
      `Inserted records: ${insertedScans.length}`
    );

    console.log(
      `Phishing records: ${phishingCount}`
    );

    console.log(
      `Safe records: ${safeCount}`
    );

    console.log(
      `Assigned user: ${user.email}`
    );

    console.log(
      "Existing genuine scans were preserved."
    );

    process.exit(0);
  } catch (error) {
    console.error(
      "\nDatabase seed failed:"
    );

    console.error(
      error.message
    );

    process.exit(1);
  }
};


seedEmailScans();