import {
  Activity,
  AlertTriangle,
  CalendarDays,
  CheckCircle2,
  Download,
  FileText,
  Link2,
  LockKeyhole,
  Mail,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Target,
  TrendingUp,
} from "lucide-react";

import {
  Area,
  AreaChart,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
} from "recharts";

import {
  useEffect,
  useMemo,
  useState,
} from "react";

import toast from "react-hot-toast";

import api from "../api/axios";


const REPORT_PERIODS = {
  all: {
    label: "All time",
    days: null,
  },
  seven: {
    label: "Last 7 days",
    days: 7,
  },
  thirty: {
    label: "Last 30 days",
    days: 30,
  },
  ninety: {
    label: "Last 90 days",
    days: 90,
  },
};


const Reports = () => {
  const [dashboardData, setDashboardData] =
    useState(null);

  const [historyData, setHistoryData] =
    useState([]);

  const [loading, setLoading] =
    useState(true);

  const [selectedPeriod, setSelectedPeriod] =
    useState("all");


  const loadReportData = async () => {
    try {
      setLoading(true);

      const [
        dashboardResponse,
        historyResponse,
      ] = await Promise.all([
        api.get("/dashboard/summary"),

        api.get(
          "/scans/history?page=1&limit=50"
        ),
      ]);

      setDashboardData(
        dashboardResponse.data
      );

      setHistoryData(
        historyResponse.data?.scans || []
      );
    } catch (error) {
      toast.error(
        error.response?.data?.message ||
          "Unable to generate report"
      );
    } finally {
      setLoading(false);
    }
  };


  useEffect(() => {
    loadReportData();
  }, []);


  const filteredHistory = useMemo(() => {
    const period =
      REPORT_PERIODS[selectedPeriod];

    if (!period?.days) {
      return historyData;
    }

    const startDate = new Date();

    startDate.setDate(
      startDate.getDate() - period.days
    );

    return historyData.filter((scan) => {
      return (
        new Date(scan.createdAt) >=
        startDate
      );
    });
  }, [historyData, selectedPeriod]);


  const reportSummary = useMemo(() => {
    const totalScans =
      filteredHistory.length;

    const phishingScans =
      filteredHistory.filter(
        (scan) =>
          scan.verdict === "phishing"
      ).length;

    const suspiciousScans =
      filteredHistory.filter(
        (scan) =>
          scan.verdict === "suspicious"
      ).length;

    const safeScans =
      filteredHistory.filter(
        (scan) => scan.verdict === "safe"
      ).length;

    const threatsDetected =
      phishingScans + suspiciousScans;

    const threatRate =
      totalScans > 0
        ? Math.round(
            (threatsDetected / totalScans) *
              100
          )
        : 0;

    const totalRisk =
      filteredHistory.reduce(
        (sum, scan) =>
          sum + Number(scan.riskScore || 0),
        0
      );

    const averageRiskScore =
      totalScans > 0
        ? Math.round(totalRisk / totalScans)
        : 0;

    const emailScans =
      filteredHistory.filter(
        (scan) =>
          scan.scanType === "email"
      ).length;

    const urlScans =
      filteredHistory.filter(
        (scan) => scan.scanType === "url"
      ).length;

    return {
      totalScans,
      phishingScans,
      suspiciousScans,
      safeScans,
      threatsDetected,
      threatRate,
      averageRiskScore,
      emailScans,
      urlScans,
    };
  }, [filteredHistory]);


  const chartData = [
    {
      name: "Safe",
      value: reportSummary.safeScans,
      color: "#37e6a2",
    },
    {
      name: "Suspicious",
      value:
        reportSummary.suspiciousScans,
      color: "#ffa928",
    },
    {
      name: "Phishing",
      value:
        reportSummary.phishingScans,
      color: "#f04452",
    },
  ];


  const trendData = useMemo(() => {
    if (filteredHistory.length === 0) {
      return [
        {
          label: "No data",
          scans: 0,
        },
      ];
    }

    const groupedScans = {};

    filteredHistory.forEach((scan) => {
      const date = new Date(
        scan.createdAt
      ).toLocaleDateString("en-US", {
        month: "short",
        day: "numeric",
      });

      groupedScans[date] =
        (groupedScans[date] || 0) + 1;
    });

    return Object.entries(groupedScans)
      .map(([label, scans]) => ({
        label,
        scans,
      }))
      .slice(-10);
  }, [filteredHistory]);


  const getRiskStatus = () => {
    const risk =
      reportSummary.averageRiskScore;

    if (risk >= 70) {
      return {
        label: "HIGH RISK",
        message:
          "Immediate security review is recommended.",
        className: "high",
      };
    }

    if (risk >= 40) {
      return {
        label: "ELEVATED RISK",
        message:
          "Stay vigilant. Elevated risks detected.",
        className: "medium",
      };
    }

    return {
      label: "LOW RISK",
      message:
        "The current security posture is stable.",
      className: "low",
    };
  };


  const riskStatus = getRiskStatus();


  const highestRiskScan = useMemo(() => {
    if (filteredHistory.length === 0) {
      return null;
    }

    return [...filteredHistory].sort(
      (firstScan, secondScan) =>
        Number(secondScan.riskScore || 0) -
        Number(firstScan.riskScore || 0)
    )[0];
  }, [filteredHistory]);


  const getReportDateRange = () => {
    if (filteredHistory.length === 0) {
      return "No scan records";
    }

    const sortedDates = filteredHistory
      .map((scan) => new Date(scan.createdAt))
      .sort(
        (firstDate, secondDate) =>
          firstDate - secondDate
      );

    const firstDate =
      sortedDates[0].toLocaleDateString();

    const lastDate =
      sortedDates[
        sortedDates.length - 1
      ].toLocaleDateString();

    return firstDate === lastDate
      ? firstDate
      : `${firstDate} - ${lastDate}`;
  };


  const downloadCSV = () => {
    if (filteredHistory.length === 0) {
      toast.error(
        "There are no scan records to export"
      );

      return;
    }

    const headings = [
      "Scan ID",
      "Type",
      "Target",
      "Verdict",
      "Risk Score",
      "Confidence",
      "Detection Method",
      "Date",
    ];

    const rows = filteredHistory.map(
      (scan) => [
        scan._id,
        scan.scanType,

        scan.scanType === "email"
          ? scan.emailData?.subject ||
            "No subject"
          : scan.submittedUrl,

        scan.verdict,
        scan.riskScore,
        scan.confidence,
        scan.detectionMethod,

        new Date(
          scan.createdAt
        ).toLocaleString(),
      ]
    );

    const escapeCSVValue = (value) => {
      const stringValue = String(
        value ?? ""
      );

      return `"${stringValue.replace(
        /"/g,
        '""'
      )}"`;
    };

    const csvContent = [
      headings
        .map(escapeCSVValue)
        .join(","),

      ...rows.map((row) =>
        row
          .map(escapeCSVValue)
          .join(",")
      ),
    ].join("\n");

    const file = new Blob(
      [csvContent],
      {
        type: "text/csv;charset=utf-8;",
      }
    );

    const downloadURL =
      URL.createObjectURL(file);

    const link =
      document.createElement("a");

    link.href = downloadURL;

    link.download =
      `phishguard-security-report-${
        new Date()
          .toISOString()
          .split("T")[0]
      }.csv`;

    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);

    URL.revokeObjectURL(downloadURL);

    toast.success(
      "Security report downloaded"
    );
  };


  if (loading) {
    return (
      <div className="content-loader">
        <div className="loader-shield">
          PG
        </div>

        <p>
          Generating security intelligence
          report...
        </p>
      </div>
    );
  }


  const statisticCards = [
    {
      title: "Total scans",
      value: reportSummary.totalScans,
      comparison: "18.6% vs last period",
      icon: FileText,
      color: "blue",
      trend: [2, 4, 3, 6, 5, 8, 6],
    },
    {
      title: "Threats detected",
      value:
        reportSummary.threatsDetected,
      comparison: `${reportSummary.threatRate}% detection rate`,
      icon: ShieldAlert,
      color: "red",
      trend: [1, 2, 2, 4, 3, 5, 4],
    },
    {
      title: "Threat rate",
      value: `${reportSummary.threatRate}%`,
      comparison: "Across selected period",
      icon: TrendingUp,
      color: "purple",
      trend: [2, 3, 5, 4, 6, 5, 7],
    },
    {
      title: "Average risk",
      value:
        `${reportSummary.averageRiskScore}%`,
      comparison: "Combined threat exposure",
      icon: Target,
      color: "yellow",
      trend: [3, 5, 4, 7, 6, 8, 5],
    },
  ];


  return (
    <div className="modern-reports-page">
      <section className="reports-page-heading">
        <div className="reports-heading-content">
          <div>
            <p className="section-label">
              SECURITY REPORTING

              <span className="live-report-badge">
                LIVE REPORTING
              </span>
            </p>

            <h1>Threat Analysis Report</h1>

            <p>
              Review security performance,
              threat trends, and risk metrics
              across your environment.
            </p>
          </div>
        </div>

        <div className="reports-heading-actions">
          <label className="report-period-select">
            <CalendarDays size={17} />

            <select
              value={selectedPeriod}
              onChange={(event) =>
                setSelectedPeriod(
                  event.target.value
                )
              }
            >
              {Object.entries(
                REPORT_PERIODS
              ).map(([value, period]) => (
                <option
                  key={value}
                  value={value}
                >
                  {period.label}
                </option>
              ))}
            </select>
          </label>

          <button
            type="button"
            className="modern-report-export"
            onClick={downloadCSV}
          >
            <Download size={17} />
            EXPORT CSV
          </button>
        </div>
      </section>


      <section className="reports-statistics-grid">
        {statisticCards.map((card) => {
          const Icon = card.icon;

          const sparklineData =
            card.trend.map(
              (value, index) => ({
                index,
                value,
              })
            );

          return (
            <article
              className={
                `report-stat-card ${card.color}`
              }
              key={card.title}
            >
              <div className="report-stat-main">
                <div className="report-stat-icon">
                  <Icon size={22} />
                </div>

                <div>
                  <span>{card.title}</span>
                  <strong>{card.value}</strong>
                </div>
              </div>

              <div className="report-stat-footer">
                <small>
                  <TrendingUp size={12} />
                  {card.comparison}
                </small>

                <div className="report-sparkline">
                  <ResponsiveContainer
                    width="100%"
                    height="100%"
                  >
                    <AreaChart
                      data={sparklineData}
                    >
                      <defs>
                        <linearGradient
                          id={`report-gradient-${card.color}`}
                          x1="0"
                          y1="0"
                          x2="0"
                          y2="1"
                        >
                          <stop
                            offset="0%"
                            stopColor="currentColor"
                            stopOpacity={0.45}
                          />

                          <stop
                            offset="100%"
                            stopColor="currentColor"
                            stopOpacity={0}
                          />
                        </linearGradient>
                      </defs>

                      <Area
                        type="monotone"
                        dataKey="value"
                        stroke="currentColor"
                        strokeWidth={2}
                        fill={
                          `url(#report-gradient-${card.color})`
                        }
                        isAnimationActive
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </article>
          );
        })}
      </section>


      <section className="reports-primary-grid">
        <article className="modern-report-panel detection-overview-panel">
          <div className="modern-report-panel-header">
            <div>
              <span>
                DETECTION OVERVIEW
              </span>

              <h2>
                Distribution of scan verdicts
              </h2>
            </div>

            <ShieldAlert size={19} />
          </div>

          <div className="report-detection-content">
            {reportSummary.totalScans > 0 ? (
              <div className="modern-report-chart">
                <ResponsiveContainer
                  width="100%"
                  height={270}
                >
                  <PieChart>
                    <Pie
                      data={chartData}
                      dataKey="value"
                      nameKey="name"
                      innerRadius={72}
                      outerRadius={105}
                      paddingAngle={3}
                      stroke="rgba(255,255,255,0.15)"
                      strokeWidth={1}
                    >
                      {chartData.map(
                        (entry) => (
                          <Cell
                            key={entry.name}
                            fill={entry.color}
                          />
                        )
                      )}
                    </Pie>

                    <Tooltip
                      contentStyle={{
                        background:
                          "#0c2235",
                        border:
                          "1px solid rgba(100, 170, 220, 0.25)",
                        borderRadius: "10px",
                        color: "#ffffff",
                      }}
                    />
                  </PieChart>
                </ResponsiveContainer>

                <div className="report-chart-center">
                  <strong>
                    {reportSummary.totalScans}
                  </strong>

                  <span>TOTAL SCANS</span>
                </div>
              </div>
            ) : (
              <div className="report-empty-state">
                <FileText size={34} />

                <p>
                  No report information
                  available.
                </p>
              </div>
            )}

            <div className="modern-report-legend">
              {chartData.map((item) => {
                const percentage =
                  reportSummary.totalScans > 0
                    ? Math.round(
                        (item.value /
                          reportSummary.totalScans) *
                          100
                      )
                    : 0;

                return (
                  <div key={item.name}>
                    <i
                      style={{
                        backgroundColor:
                          item.color,
                      }}
                    />

                    <span>{item.name}</span>

                    <strong>
                      {item.value}
                      <small>
                        {percentage}%
                      </small>
                    </strong>
                  </div>
                );
              })}

              <div className="report-security-note">
                <ShieldCheck size={18} />

                <p>
                  Results are calculated using
                  explainable rule and
                  machine-learning analysis.
                </p>
              </div>
            </div>
          </div>
        </article>


        <article className="modern-report-panel security-posture-panel">
          <div className="modern-report-panel-header">
            <div>
              <span>SECURITY POSTURE</span>

              <h2>
                Overall risk assessment
              </h2>
            </div>

            <Activity size={19} />
          </div>

          <div className="report-risk-gauge">
            <div
              className="risk-gauge-track"
              style={{
                "--report-risk":
                  `${Math.min(
                    reportSummary.averageRiskScore,
                    100
                  ) * 1.8}deg`,
              }}
            >
              <div className="risk-gauge-inner">
                <strong>
                  {
                    reportSummary
                      .averageRiskScore
                  }
                  %
                </strong>

                <span>AVERAGE RISK</span>
              </div>
            </div>

            <div
              className={
                `report-risk-status ${riskStatus.className}`
              }
            >
              {riskStatus.label}
            </div>

            <p>{riskStatus.message}</p>
          </div>

          <div className="report-risk-scale">
            <span>LOW</span>
            <span>MEDIUM</span>
            <span>HIGH</span>
          </div>
        </article>
      </section>


      <section className="reports-secondary-grid">
        <article className="modern-report-panel channel-performance-panel">
          <div className="modern-report-panel-header">
            <div>
              <span>
                SCAN CHANNEL PERFORMANCE
              </span>

              <h2>
                Analysis by security channel
              </h2>
            </div>

            <Activity size={19} />
          </div>

          <div className="modern-channel-report">
            <div className="report-channel-row">
              <div className="channel-icon email">
                <Mail size={18} />
              </div>

              <div className="channel-progress-content">
                <div>
                  <strong>Email</strong>

                  <span>
                    {
                      reportSummary.emailScans
                    }{" "}
                    scans
                  </span>
                </div>

                <div className="modern-report-progress">
                  <i
                    className="email"
                    style={{
                      width:
                        reportSummary.totalScans >
                        0
                          ? `${
                              (reportSummary.emailScans /
                                reportSummary.totalScans) *
                              100
                            }%`
                          : "0%",
                    }}
                  />
                </div>
              </div>

              <strong className="channel-percentage">
                {reportSummary.totalScans > 0
                  ? Math.round(
                      (reportSummary.emailScans /
                        reportSummary.totalScans) *
                        100
                    )
                  : 0}
                %
              </strong>
            </div>

            <div className="report-channel-row">
              <div className="channel-icon url">
                <Link2 size={18} />
              </div>

              <div className="channel-progress-content">
                <div>
                  <strong>URL</strong>

                  <span>
                    {reportSummary.urlScans} scans
                  </span>
                </div>

                <div className="modern-report-progress">
                  <i
                    className="url"
                    style={{
                      width:
                        reportSummary.totalScans >
                        0
                          ? `${
                              (reportSummary.urlScans /
                                reportSummary.totalScans) *
                              100
                            }%`
                          : "0%",
                    }}
                  />
                </div>
              </div>

              <strong className="channel-percentage">
                {reportSummary.totalScans > 0
                  ? Math.round(
                      (reportSummary.urlScans /
                        reportSummary.totalScans) *
                        100
                    )
                  : 0}
                %
              </strong>
            </div>
          </div>

          <div className="report-trend-preview">
            <div>
              <span>
                SCAN ACTIVITY TREND
              </span>

              <strong>
                {reportSummary.totalScans} total
              </strong>
            </div>

            <ResponsiveContainer
              width="100%"
              height={90}
            >
              <AreaChart data={trendData}>
                <defs>
                  <linearGradient
                    id="reportActivityGradient"
                    x1="0"
                    y1="0"
                    x2="0"
                    y2="1"
                  >
                    <stop
                      offset="0%"
                      stopColor="#38bdf8"
                      stopOpacity={0.38}
                    />

                    <stop
                      offset="100%"
                      stopColor="#38bdf8"
                      stopOpacity={0}
                    />
                  </linearGradient>
                </defs>

                <Area
                  type="monotone"
                  dataKey="scans"
                  stroke="#45c7ff"
                  strokeWidth={2}
                  fill="url(#reportActivityGradient)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </article>


        <article className="modern-report-panel intelligence-summary-panel">
          <div className="modern-report-panel-header">
            <div>
              <span>
                THREAT INTELLIGENCE SUMMARY
              </span>

              <h2>
                Key insights from your scans
              </h2>
            </div>

            <Sparkles size={19} />
          </div>

          <div className="report-insight-grid">
            <div className="report-insight danger">
              <ShieldAlert size={19} />

              <div>
                <span>Detected threats</span>

                <strong>
                  {
                    reportSummary
                      .threatsDetected
                  }
                </strong>

                <small>
                  Phishing and suspicious
                  content
                </small>
              </div>
            </div>

            <div className="report-insight safe">
              <CheckCircle2 size={19} />

              <div>
                <span>Safe results</span>

                <strong>
                  {reportSummary.safeScans}
                </strong>

                <small>
                  Clean content detected
                </small>
              </div>
            </div>

            <div className="report-insight warning">
              <AlertTriangle size={19} />

              <div>
                <span>
                  Highest-risk verdict
                </span>

                <strong>
                  {highestRiskScan?.verdict ||
                    "No data"}
                </strong>

                <small>
                  {highestRiskScan
                    ? `${highestRiskScan.riskScore}/100 risk score`
                    : "No scans available"}
                </small>
              </div>
            </div>

            <div className="report-insight privacy">
              <LockKeyhole size={19} />

              <div>
                <span>Privacy first</span>

                <strong>100%</strong>

                <small>
                  Sensitive bodies excluded
                  from CSV
                </small>
              </div>
            </div>
          </div>
        </article>
      </section>


      <section className="recent-report-export">
        <div className="recent-export-icon">
          <FileText size={21} />
        </div>

        <div className="recent-export-title">
          <span>RECENT EXPORT</span>

          <strong>
            PhishGuard Threat Analysis Report
          </strong>

          <small>
            Ready to generate as a CSV file
          </small>
        </div>

        <div className="recent-export-detail">
          <span>Records</span>
          <strong>
            {filteredHistory.length} scans
          </strong>
        </div>

        <div className="recent-export-detail">
          <span>Date range</span>
          <strong>
            {getReportDateRange()}
          </strong>
        </div>

        <div className="recent-export-detail">
          <span>Format</span>
          <strong>CSV security report</strong>
        </div>

        <button
          type="button"
          onClick={downloadCSV}
        >
          <Download size={16} />
          Download
        </button>
      </section>
    </div>
  );
};


export default Reports;