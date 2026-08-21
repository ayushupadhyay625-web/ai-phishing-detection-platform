import {
  Activity,
  Download,
  FileText,
  Mail,
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


const Reports = () => {
  const [dashboardData, setDashboardData] =
    useState(null);

  const [historyData, setHistoryData] =
    useState([]);

  const [loading, setLoading] =
    useState(true);


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
        historyResponse.data.scans
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


  const downloadCSV = () => {
    if (historyData.length === 0) {
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


    const rows = historyData.map((scan) => [
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
    ]);


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
      headings.map(escapeCSVValue).join(","),

      ...rows.map((row) =>
        row.map(escapeCSVValue).join(",")
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

        <p>Generating security report...</p>
      </div>
    );
  }


  const summary =
    dashboardData?.summary || {
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


  const chartData = [
    {
      name: "Safe",
      value: summary.safeScans,
      color: "#42efa7",
    },

    {
      name: "Suspicious",
      value: summary.suspiciousScans,
      color: "#f2c85b",
    },

    {
      name: "Phishing",
      value: summary.phishingScans,
      color: "#ff657d",
    },
  ];


  return (
    <>
      <section className="page-heading">
        <div>
          <p className="section-label">
            SECURITY REPORTING
          </p>

          <h1>Threat Analysis Report</h1>

          <p>
            Review security performance and export
            recorded scan information.
          </p>
        </div>

        <button
          type="button"
          className="primary-button report-download"
          onClick={downloadCSV}
        >
          <Download size={17} />

          DOWNLOAD CSV
        </button>
      </section>


      <section className="report-summary-grid">
        <article>
          <FileText size={21} />

          <span>Total scans</span>

          <strong>{summary.totalScans}</strong>
        </article>

        <article>
          <ShieldAlert size={21} />

          <span>Threats detected</span>

          <strong>
            {summary.threatsDetected}
          </strong>
        </article>

        <article>
          <Activity size={21} />

          <span>Threat rate</span>

          <strong>
            {summary.threatRate}%
          </strong>
        </article>

        <article>
          <ShieldCheck size={21} />

          <span>Average risk</span>

          <strong>
            {summary.averageRiskScore}%
          </strong>
        </article>
      </section>


      <section className="report-grid">
        <article className="panel">
          <div className="panel-header">
            <div>
              <span className="panel-label">
                VERDICT BREAKDOWN
              </span>

              <h2>Detection results</h2>
            </div>

            <ShieldAlert size={20} />
          </div>


          <div className="report-chart">
            {summary.totalScans > 0 ? (
              <ResponsiveContainer
                width="100%"
                height={280}
              >
                <PieChart>
                  <Pie
                    data={chartData}
                    dataKey="value"
                    nameKey="name"
                    innerRadius={68}
                    outerRadius={100}
                    paddingAngle={4}
                  >
                    {chartData.map((entry) => (
                      <Cell
                        key={entry.name}
                        fill={entry.color}
                      />
                    ))}
                  </Pie>

                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="empty-state">
                No report information available.
              </div>
            )}
          </div>


          <div className="chart-legend">
            {chartData.map((item) => (
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


        <article className="panel">
          <div className="panel-header">
            <div>
              <span className="panel-label">
                SCAN CHANNELS
              </span>

              <h2>Analysis sources</h2>
            </div>

            <Mail size={20} />
          </div>


          <div className="channel-report">
            <div>
              <span>Email scans</span>

              <strong>
                {scanTypes.emailScans}
              </strong>

              <div className="report-progress">
                <i
                  style={{
                    width:
                      summary.totalScans > 0
                        ? `${
                            (
                              scanTypes.emailScans /
                              summary.totalScans
                            ) * 100
                          }%`
                        : "0%",
                  }}
                />
              </div>
            </div>


            <div>
              <span>URL scans</span>

              <strong>
                {scanTypes.urlScans}
              </strong>

              <div className="report-progress">
                <i
                  style={{
                    width:
                      summary.totalScans > 0
                        ? `${
                            (
                              scanTypes.urlScans /
                              summary.totalScans
                            ) * 100
                          }%`
                        : "0%",
                  }}
                />
              </div>
            </div>


            <div className="report-note">
              <FileText size={20} />

              <p>
                The downloadable report contains
                scan metadata and threat scores.
                Complete email bodies are excluded
                to protect sensitive information.
              </p>
            </div>
          </div>
        </article>
      </section>
    </>
  );
};


export default Reports;