import PhishingScan from "../models/PhishingScan.js";


// GET /api/dashboard/summary
export const getDashboardSummary = async (
  req,
  res
) => {
  try {
    const accessFilter =
      req.user.role === "admin"
        ? {}
        : {
            scannedBy: req.user._id,
          };

    const [
      totalScans,
      phishingScans,
      suspiciousScans,
      safeScans,
      emailScans,
      urlScans,
      averageRiskResult,
      recentScans,
    ] = await Promise.all([
      PhishingScan.countDocuments(accessFilter),

      PhishingScan.countDocuments({
        ...accessFilter,
        verdict: "phishing",
      }),

      PhishingScan.countDocuments({
        ...accessFilter,
        verdict: "suspicious",
      }),

      PhishingScan.countDocuments({
        ...accessFilter,
        verdict: "safe",
      }),

      PhishingScan.countDocuments({
        ...accessFilter,
        scanType: "email",
      }),

      PhishingScan.countDocuments({
        ...accessFilter,
        scanType: "url",
      }),

      PhishingScan.aggregate([
        {
          $match: accessFilter,
        },
        {
          $group: {
            _id: null,
            averageRiskScore: {
              $avg: "$riskScore",
            },
          },
        },
      ]),

      PhishingScan.find(accessFilter)
        .select(
          "scanType verdict riskScore confidence detectionMethod createdAt"
        )
        .sort({
          createdAt: -1,
        })
        .limit(5),
    ]);

    const averageRiskScore =
      averageRiskResult.length > 0
        ? Math.round(
            averageRiskResult[0].averageRiskScore
          )
        : 0;

    const threatsDetected =
      phishingScans + suspiciousScans;

    const threatRate =
      totalScans > 0
        ? Number(
            (
              (threatsDetected / totalScans) *
              100
            ).toFixed(2)
          )
        : 0;

    return res.status(200).json({
      success: true,

      summary: {
        totalScans,
        phishingScans,
        suspiciousScans,
        safeScans,
        threatsDetected,
        threatRate,
        averageRiskScore,
      },

      scanTypes: {
        emailScans,
        urlScans,
      },

      recentScans,
    });
  } catch (error) {
    console.error(
      "Dashboard summary error:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        "Unable to retrieve dashboard summary",
    });
  }
};


// GET /api/dashboard/trends
export const getThreatTrends = async (
  req,
  res
) => {
  try {
    const requestedDays = Number.parseInt(
      req.query.days,
      10
    );

    const days = [7, 14, 30].includes(requestedDays)
      ? requestedDays
      : 7;

    const startDate = new Date();

    startDate.setDate(
      startDate.getDate() - (days - 1)
    );

    startDate.setHours(0, 0, 0, 0);

    const matchFilter = {
      createdAt: {
        $gte: startDate,
      },
    };

    if (req.user.role !== "admin") {
      matchFilter.scannedBy = req.user._id;
    }

    const trends = await PhishingScan.aggregate([
      {
        $match: matchFilter,
      },
      {
        $group: {
          _id: {
            date: {
              $dateToString: {
                format: "%Y-%m-%d",
                date: "$createdAt",
              },
            },
            verdict: "$verdict",
          },
          count: {
            $sum: 1,
          },
        },
      },
      {
        $sort: {
          "_id.date": 1,
        },
      },
    ]);

    return res.status(200).json({
      success: true,
      period: {
        days,
        startDate,
        endDate: new Date(),
      },
      trends,
    });
  } catch (error) {
    console.error(
      "Threat trends error:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        "Unable to retrieve threat trends",
    });
  }
};