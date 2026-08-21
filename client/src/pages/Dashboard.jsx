import {
  Activity,
  AlertTriangle,
  Mail,
  ScanSearch,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";

import {
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
} from "recharts";

import {
  useEffect,
  useState,
} from "react";

import toast from "react-hot-toast";

import api from "../api/axios";


const Dashboard = () => {
  const [dashboardData, setDashboardData] =
    useState(null);

  const [loading, setLoading] =
    useState(true);


  const loadDashboard = async () => {
    try {
      setLoading(true);

      const response = await api.get(
        "/dashboard/summary"
      );

      setDashboardData(response.data);
    } catch (error) {
      toast.error(
        error.response?.data?.message ||
          "Unable to load dashboard"
      );
    } finally {
      setLoading(false);
    }
  };


  useEffect(() => {
    loadDashboard();
  }, []);


  if (loading) {
    return (
      <div className="content-loader">
        <div className="loader-shield">
          PG
        </div>

        <p>Loading security intelligence...</p>
      </div>
    );
  }


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


  const verdictChartData = [
    {
      name: "Safe",
      value: summary.safeScans,
      color: "#3de6a5",
    },
    {
      name: "Suspicious",
      value: summary.suspiciousScans,
      color: "#f4c95d",
    },
    {
      name: "Phishing",
      value: summary.phishingScans,
      color: "#ff647c",
    },
  ];


  const statisticCards = [
    {
      title: "Total scans",
      value: summary.totalScans,
      description: "All analyzed threats",
      icon: ScanSearch,
      color: "blue",
    },
    {
      title: "Threats detected",
      value: summary.threatsDetected,
      description: `${summary.threatRate}% detection rate`,
      icon: ShieldAlert,
      color: "red",
    },
    {
      title: "Safe results",
      value: summary.safeScans,
      description: "No major indicators",
      icon: ShieldCheck,
      color: "green",
    },
    {
      title: "Average risk",
      value: `${summary.averageRiskScore}%`,
      description: "Across all scans",
      icon: Activity,
      color: "yellow",
    },
  ];


  return (
    <>
      <section className="page-heading">
        <div>
          <p className="section-label">
            SECURITY OVERVIEW
          </p>

          <h1>Threat Intelligence Dashboard</h1>

          <p>
            Monitor phishing detections, risk
            levels, and recent security activity.
          </p>
        </div>

        <button
          type="button"
          className="secondary-button"
          onClick={loadDashboard}
        >
          Refresh intelligence
        </button>
      </section>


      <section className="statistics-grid">
        {statisticCards.map((card) => {
          const Icon = card.icon;

          return (
            <article
              className="statistic-card"
              key={card.title}
            >
              <div
                className={
                  `statistic-icon ${card.color}`
                }
              >
                <Icon size={22} />
              </div>

              <div>
                <span>{card.title}</span>

                <strong>{card.value}</strong>

                <small>
                  {card.description}
                </small>
              </div>
            </article>
          );
        })}
      </section>


      <section className="dashboard-grid">
        <article className="panel verdict-panel">
          <div className="panel-header">
            <div>
              <span className="panel-label">
                DETECTION DISTRIBUTION
              </span>

              <h2>Threat verdicts</h2>
            </div>

            <AlertTriangle size={20} />
          </div>


          {summary.totalScans > 0 ? (
            <div className="chart-container">
              <ResponsiveContainer
                width="100%"
                height={260}
              >
                <PieChart>
                  <Pie
                    data={verdictChartData}
                    dataKey="value"
                    nameKey="name"
                    innerRadius={65}
                    outerRadius={95}
                    paddingAngle={4}
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

              <div className="chart-center">
                <strong>
                  {summary.totalScans}
                </strong>

                <span>TOTAL</span>
              </div>
            </div>
          ) : (
            <div className="empty-state">
              <ShieldCheck size={36} />

              <p>No scans recorded yet.</p>
            </div>
          )}


          <div className="chart-legend">
            {verdictChartData.map((item) => (
              <div key={item.name}>
                <i
                  style={{
                    backgroundColor:
                      item.color,
                  }}
                />

                <span>{item.name}</span>

                <strong>{item.value}</strong>
              </div>
            ))}
          </div>
        </article>


        <article className="panel activity-panel">
          <div className="panel-header">
            <div>
              <span className="panel-label">
                LATEST ANALYSES
              </span>

              <h2>Recent scan activity</h2>
            </div>

            <Activity size={20} />
          </div>


          <div className="recent-scan-list">
            {recentScans.length > 0 ? (
              recentScans.map((scan) => (
                <div
                  className="recent-scan"
                  key={scan._id}
                >
                  <div
                    className={
                      `scan-type-icon ${scan.scanType}`
                    }
                  >
                    {scan.scanType === "email"
                      ? <Mail size={18} />
                      : <ScanSearch size={18} />}
                  </div>

                  <div className="recent-scan-info">
                    <strong>
                      {scan.scanType === "email"
                        ? "Email analysis"
                        : "URL analysis"}
                    </strong>

                    <span>
                      {new Date(
                        scan.createdAt
                      ).toLocaleString()}
                    </span>
                  </div>

                  <div
                    className={
                      `verdict-badge ${scan.verdict}`
                    }
                  >
                    {scan.verdict}
                  </div>

                  <strong className="risk-value">
                    {scan.riskScore}
                  </strong>
                </div>
              ))
            ) : (
              <div className="empty-state">
                <ShieldCheck size={36} />

                <p>
                  Your recent scans will appear
                  here.
                </p>
              </div>
            )}
          </div>


          <div className="scan-type-summary">
            <div>
              <Mail size={18} />

              <span>Email scans</span>

              <strong>
                {scanTypes.emailScans}
              </strong>
            </div>

            <div>
              <ScanSearch size={18} />

              <span>URL scans</span>

              <strong>
                {scanTypes.urlScans}
              </strong>
            </div>
          </div>
        </article>
      </section>
    </>
  );
};


export default Dashboard;