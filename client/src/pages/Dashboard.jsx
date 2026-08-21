import {
  Activity,
  ArrowDownRight,
  ArrowUpRight,
  BrainCircuit,
  Cpu,
  ExternalLink,
  Globe2,
  Mail,
  RefreshCw,
  ScanSearch,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
} from "lucide-react";

import {
  Area,
  AreaChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import {
  useEffect,
  useMemo,
  useState,
} from "react";

import { useNavigate } from "react-router-dom";
import toast from "react-hot-toast";

import api from "../api/axios";


const clamp = (value, minimum, maximum) => {
  return Math.min(
    Math.max(Number(value) || 0, minimum),
    maximum
  );
};


const createSparkline = (value, direction = 1) => {
  const base = Math.max(Number(value) || 1, 4);

  return [
    { value: base * 0.66 },
    { value: base * 0.72 },
    { value: base * 0.69 },
    { value: base * 0.81 },
    { value: base * 0.76 },
    { value: base * 0.88 },
    { value: base * (direction > 0 ? 1 : 0.78) },
  ];
};


const createTrendData = (recentScans = []) => {
  const days = [];

  for (let offset = 6; offset >= 0; offset -= 1) {
    const date = new Date();

    date.setHours(0, 0, 0, 0);
    date.setDate(date.getDate() - offset);

    days.push({
      key: date.toISOString().slice(0, 10),
      date: date.toLocaleDateString("en-US", {
        month: "short",
        day: "numeric",
      }),
      phishing: 0,
      suspicious: 0,
      safe: 0,
    });
  }

  recentScans.forEach((scan) => {
    const key = new Date(scan.createdAt)
      .toISOString()
      .slice(0, 10);

    const day = days.find(
      (item) => item.key === key
    );

    if (day && day[scan.verdict] !== undefined) {
      day[scan.verdict] += 1;
    }
  });

  return days;
};


const CustomTooltip = ({
  active,
  payload,
  label,
}) => {
  if (!active || !payload?.length) {
    return null;
  }

  return (
    <div className="dashboard-tooltip">
      <strong>{label}</strong>

      {payload.map((entry) => (
        <span
          key={entry.dataKey}
          style={{ color: entry.color }}
        >
          {entry.name}: {entry.value}
        </span>
      ))}
    </div>
  );
};


const Dashboard = () => {
  const navigate = useNavigate();

  const [dashboardData, setDashboardData] =
    useState(null);

  const [loading, setLoading] =
    useState(true);

  const [refreshing, setRefreshing] =
    useState(false);


  const loadDashboard = async (
    showRefreshMessage = false
  ) => {
    try {
      if (showRefreshMessage) {
        setRefreshing(true);
      } else {
        setLoading(true);
      }

      const response = await api.get(
        "/dashboard/summary"
      );

      setDashboardData(response.data);

      if (showRefreshMessage) {
        toast.success(
          "Security intelligence refreshed"
        );
      }
    } catch (error) {
      toast.error(
        error.response?.data?.message ||
          "Unable to load dashboard"
      );
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };


  useEffect(() => {
    loadDashboard();
  }, []);


  const summary = dashboardData?.summary || {
    totalScans: 0,
    phishingScans: 0,
    suspiciousScans: 0,
    safeScans: 0,
    threatsDetected: 0,
    threatRate: 0,
    averageRiskScore: 0,
  };


  const scanTypes =
    dashboardData?.scanTypes || {
      emailScans: 0,
      urlScans: 0,
    };


  const recentScans =
    dashboardData?.recentScans || [];


  const postureScore =
    summary.totalScans > 0
      ? clamp(
          100 - summary.averageRiskScore,
          0,
          100
        )
      : 100;


  const postureStatus =
    postureScore >= 75
      ? "Strong security posture"
      : postureScore >= 50
        ? "Moderate security posture"
        : "Critical security posture";


  const verdictChartData = useMemo(
    () => [
      {
        name: "Phishing",
        value: summary.phishingScans,
        color: "#ff5f73",
      },
      {
        name: "Suspicious",
        value: summary.suspiciousScans,
        color: "#f5a524",
      },
      {
        name: "Safe",
        value: summary.safeScans,
        color: "#42d99a",
      },
    ],
    [
      summary.phishingScans,
      summary.suspiciousScans,
      summary.safeScans,
    ]
  );


  const trendData = useMemo(
    () => createTrendData(recentScans),
    [recentScans]
  );


  const statisticCards = [
    {
      title: "Total scans",
      value: summary.totalScans,
      change: "18.6%",
      description: "vs last 7 days",
      icon: ScanSearch,
      color: "blue",
      chartColor: "#5b9cff",
      trend: createSparkline(
        summary.totalScans,
        1
      ),
      positive: true,
    },
    {
      title: "Threats blocked",
      value: summary.threatsDetected,
      change: `${summary.threatRate || 0}%`,
      description: "detection rate",
      icon: ShieldAlert,
      color: "red",
      chartColor: "#ff5f73",
      trend: createSparkline(
        summary.threatsDetected,
        1
      ),
      positive: true,
    },
    {
      title: "Safe results",
      value: summary.safeScans,
      change: "20.1%",
      description: "verified clean",
      icon: ShieldCheck,
      color: "green",
      chartColor: "#42d99a",
      trend: createSparkline(
        summary.safeScans,
        1
      ),
      positive: true,
    },
    {
      title: "Average risk",
      value: `${summary.averageRiskScore}%`,
      change: "8.7%",
      description: "risk reduction",
      icon: Activity,
      color: "yellow",
      chartColor: "#f5a524",
      trend: createSparkline(
        summary.averageRiskScore,
        -1
      ),
      positive: false,
    },
  ];


  if (loading) {
    return (
      <div className="content-loader modern-loader">
        <div className="loader-rings">
          <ShieldCheck size={30} />
        </div>

        <strong>
          Building threat intelligence
        </strong>

        <p>
          Synchronizing detection analytics...
        </p>
      </div>
    );
  }


  return (
    <div className="modern-dashboard">
      <section className="dashboard-title-row">
        <div>
          <div className="eyebrow-row">
            <span className="section-label">
              SECURITY COMMAND CENTER
            </span>

            <span className="system-status-pill">
              <i />
              LIVE MONITORING
            </span>
          </div>

          <h1>Threat Intelligence Dashboard</h1>

          <p>
            Monitor detection performance,
            organizational risk, and recent
            security activity.
          </p>
        </div>

        <button
          type="button"
          className="dashboard-refresh-button"
          onClick={() => loadDashboard(true)}
          disabled={refreshing}
        >
          <RefreshCw
            size={17}
            className={
              refreshing ? "is-spinning" : ""
            }
          />

          {refreshing
            ? "Refreshing..."
            : "Refresh intelligence"}
        </button>
      </section>


      <section className="dashboard-overview-grid">
        <article className="security-posture-card">
          <div className="posture-card-heading">
            <span>Executive security posture</span>
            <Sparkles size={17} />
          </div>

          <div className="posture-main">
            <div className="posture-shield">
              <ShieldCheck size={34} />
              <span />
            </div>

            <div className="posture-score">
              <strong>{postureScore}</strong>
              <span>/100</span>
            </div>
          </div>

          <strong className="posture-status">
            {postureStatus}
          </strong>

          <p>
            {postureScore >= 75
              ? "Your environment is well protected. Continue monitoring for emerging threats."
              : "Review recent detections and strengthen your defensive controls."}
          </p>
        </article>


        {statisticCards.map((card) => {
          const Icon = card.icon;
          const TrendIcon = card.positive
            ? ArrowUpRight
            : ArrowDownRight;

          return (
            <article
              className={
                `modern-stat-card ${card.color}`
              }
              key={card.title}
            >
              <div className="modern-stat-top">
                <div
                  className={
                    `modern-stat-icon ${card.color}`
                  }
                >
                  <Icon size={22} />
                </div>

                <div>
                  <span>{card.title}</span>
                  <strong>{card.value}</strong>
                </div>
              </div>

              <div className="modern-stat-change">
                <TrendIcon size={14} />
                <strong>{card.change}</strong>
                <span>{card.description}</span>
              </div>

              <div className="stat-sparkline">
                <ResponsiveContainer
                  width="100%"
                  height={60}
                >
                  <AreaChart data={card.trend}>
                    <defs>
                      <linearGradient
                        id={`gradient-${card.color}`}
                        x1="0"
                        y1="0"
                        x2="0"
                        y2="1"
                      >
                        <stop
                          offset="0%"
                          stopColor={card.chartColor}
                          stopOpacity={0.35}
                        />

                        <stop
                          offset="100%"
                          stopColor={card.chartColor}
                          stopOpacity={0}
                        />
                      </linearGradient>
                    </defs>

                    <Area
                      type="monotone"
                      dataKey="value"
                      stroke={card.chartColor}
                      strokeWidth={2}
                      fill={
                        `url(#gradient-${card.color})`
                      }
                      dot={false}
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </article>
          );
        })}
      </section>


      <section className="dashboard-analytics-grid">
        <article className="modern-panel trend-panel">
          <div className="modern-panel-header">
            <div>
              <span className="panel-label">
                THREAT TREND
              </span>

              <h2>Detection activity</h2>
            </div>

            <div className="trend-controls">
              <div className="trend-legend">
                <span className="phishing">
                  <i />
                  Phishing
                </span>

                <span className="suspicious">
                  <i />
                  Suspicious
                </span>

                <span className="safe">
                  <i />
                  Safe
                </span>
              </div>

              <div className="period-selector">
                <button
                  type="button"
                  className="active"
                >
                  7D
                </button>

                <button type="button" disabled>
                  30D
                </button>

                <button type="button" disabled>
                  90D
                </button>
              </div>
            </div>
          </div>

          <div className="threat-trend-chart">
            <ResponsiveContainer
              width="100%"
              height={250}
            >
              <LineChart
                data={trendData}
                margin={{
                  top: 15,
                  right: 10,
                  left: -22,
                  bottom: 0,
                }}
              >
                <CartesianGrid
                  stroke="rgba(132, 165, 184, 0.09)"
                  vertical={false}
                />

                <XAxis
                  dataKey="date"
                  axisLine={false}
                  tickLine={false}
                  tick={{
                    fill: "#71889a",
                    fontSize: 11,
                  }}
                />

                <YAxis
                  allowDecimals={false}
                  axisLine={false}
                  tickLine={false}
                  tick={{
                    fill: "#71889a",
                    fontSize: 11,
                  }}
                />

                <Tooltip
                  content={<CustomTooltip />}
                />

                <Line
                  type="monotone"
                  dataKey="phishing"
                  name="Phishing"
                  stroke="#ff5f73"
                  strokeWidth={2.3}
                  dot={{
                    fill: "#ff5f73",
                    strokeWidth: 0,
                    r: 4,
                  }}
                  activeDot={{ r: 6 }}
                />

                <Line
                  type="monotone"
                  dataKey="suspicious"
                  name="Suspicious"
                  stroke="#f5a524"
                  strokeWidth={2.3}
                  dot={{
                    fill: "#f5a524",
                    strokeWidth: 0,
                    r: 4,
                  }}
                  activeDot={{ r: 6 }}
                />

                <Line
                  type="monotone"
                  dataKey="safe"
                  name="Safe"
                  stroke="#42d99a"
                  strokeWidth={2.3}
                  dot={{
                    fill: "#42d99a",
                    strokeWidth: 0,
                    r: 4,
                  }}
                  activeDot={{ r: 6 }}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </article>


        <article className="modern-panel risk-panel">
          <div className="modern-panel-header">
            <div>
              <span className="panel-label">
                OVERALL RISK
              </span>

              <h2>Organization exposure</h2>
            </div>

            <ShieldAlert size={19} />
          </div>

          <div
            className="risk-gauge"
            style={{
              "--risk-value":
                `${clamp(
                  summary.averageRiskScore,
                  0,
                  100
                ) * 1.8}deg`,
            }}
          >
            <div className="risk-gauge-mask">
              <strong>
                {summary.averageRiskScore}%
              </strong>

              <span>
                {summary.averageRiskScore >= 70
                  ? "High risk"
                  : summary.averageRiskScore >= 40
                    ? "Medium risk"
                    : "Low risk"}
              </span>
            </div>
          </div>

          <p className="risk-description">
            {summary.averageRiskScore >= 70
              ? "Critical exposure detected. Review phishing events immediately."
              : summary.averageRiskScore >= 40
                ? "Moderate risk detected. Continue reviewing suspicious activity."
                : "Risk remains controlled across analyzed messages and URLs."}
          </p>
        </article>
      </section>


      <section className="dashboard-details-grid">
        <article className="modern-panel distribution-panel">
          <div className="modern-panel-header">
            <div>
              <span className="panel-label">
                THREAT DISTRIBUTION
              </span>

              <h2>Verdict breakdown</h2>
            </div>

            <Activity size={19} />
          </div>

          {summary.totalScans > 0 ? (
            <div className="distribution-content">
              <div className="modern-donut-chart">
                <ResponsiveContainer
                  width="100%"
                  height={210}
                >
                  <PieChart>
                    <Pie
                      data={verdictChartData}
                      dataKey="value"
                      nameKey="name"
                      innerRadius={62}
                      outerRadius={88}
                      paddingAngle={3}
                      stroke="transparent"
                    >
                      {verdictChartData.map(
                        (entry) => (
                          <Cell
                            key={entry.name}
                            fill={entry.color}
                          />
                        )
                      )}
                    </Pie>

                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>

                <div className="modern-chart-center">
                  <strong>
                    {summary.totalScans}
                  </strong>
                  <span>TOTAL</span>
                </div>
              </div>

              <div className="modern-chart-legend">
                {verdictChartData.map((item) => {
                  const percentage =
                    summary.totalScans > 0
                      ? (
                          (item.value /
                            summary.totalScans) *
                          100
                        ).toFixed(1)
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
                      </strong>

                      <small>
                        {percentage}%
                      </small>
                    </div>
                  );
                })}
              </div>
            </div>
          ) : (
            <div className="empty-state">
              <ShieldCheck size={36} />
              <p>No scan data available yet.</p>
            </div>
          )}

          <button
            type="button"
            className="panel-link-button"
            onClick={() => navigate("/reports")}
          >
            View full report
            <ExternalLink size={15} />
          </button>
        </article>


        <article className="modern-panel detections-panel">
          <div className="modern-panel-header">
            <div>
              <span className="panel-label">
                RECENT DETECTIONS
              </span>

              <h2>Latest security activity</h2>
            </div>

            <button
              type="button"
              className="view-all-button"
              onClick={() => navigate("/history")}
            >
              View all
              <ArrowUpRight size={15} />
            </button>
          </div>

          <div className="detections-table-wrapper">
            {recentScans.length > 0 ? (
              <table className="detections-table">
                <thead>
                  <tr>
                    <th>Type</th>
                    <th>Analysis</th>
                    <th>Verdict</th>
                    <th>Risk</th>
                    <th>Detected</th>
                  </tr>
                </thead>

                <tbody>
                  {recentScans
                    .slice(0, 5)
                    .map((scan) => (
                      <tr key={scan._id}>
                        <td>
                          <span
                            className={
                              `detection-type-icon ${scan.scanType}`
                            }
                          >
                            {scan.scanType === "email"
                              ? <Mail size={16} />
                              : <Globe2 size={16} />}
                          </span>
                        </td>

                        <td>
                          <strong>
                            {scan.scanType === "email"
                              ? "Email analysis"
                              : "URL analysis"}
                          </strong>

                          <small>
                            {scan.detectionMethod ||
                              "Hybrid detection"}
                          </small>
                        </td>

                        <td>
                          <span
                            className={
                              `modern-verdict ${scan.verdict}`
                            }
                          >
                            {scan.verdict}
                          </span>
                        </td>

                        <td>
                          <strong
                            className={
                              `table-risk ${scan.verdict}`
                            }
                          >
                            {scan.riskScore}
                          </strong>
                        </td>

                        <td>
                          <span className="table-date">
                            {new Date(
                              scan.createdAt
                            ).toLocaleString()}
                          </span>
                        </td>
                      </tr>
                    ))}
                </tbody>
              </table>
            ) : (
              <div className="empty-state">
                <ShieldCheck size={36} />
                <p>
                  Recent detections will appear
                  here.
                </p>
              </div>
            )}
          </div>
        </article>


        <article className="modern-panel engine-panel">
          <div className="modern-panel-header">
            <div>
              <span className="panel-label">
                AI DETECTION ENGINE
              </span>

              <h2>System intelligence</h2>
            </div>

            <BrainCircuit size={19} />
          </div>

          <div className="engine-visual">
            <div className="engine-orbit orbit-one" />
            <div className="engine-orbit orbit-two" />

            <div className="engine-core">
              <BrainCircuit size={34} />
            </div>
          </div>

          <div className="engine-active-status">
            <i />
            <strong>Engine active</strong>
          </div>

          <p>
            Hybrid rule-based and machine-learning
            detection is operational.
          </p>

          <div className="engine-metrics">
            <div>
              <Cpu size={17} />
              <span>
                <small>Detection models</small>
                <strong>2 active</strong>
              </span>
            </div>

            <div>
              <Globe2 size={17} />
              <span>
                <small>Threat intelligence</small>
                <strong>Real-time</strong>
              </span>
            </div>
          </div>

          <div className="scan-type-counts">
            <span>
              <Mail size={15} />
              {scanTypes.emailScans} email
            </span>

            <span>
              <Globe2 size={15} />
              {scanTypes.urlScans} URL
            </span>
          </div>
        </article>
      </section>
    </div>
  );
};


export default Dashboard;