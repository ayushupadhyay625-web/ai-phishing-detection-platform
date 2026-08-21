import {
  AlertTriangle,
  BarChart3,
  CalendarDays,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  Download,
  Eye,
  FileSearch,
  FilterX,
  History,
  Link2,
  Mail,
  MoreVertical,
  Plus,
  Search,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  UserCheck,
  X,
} from "lucide-react";

import {
  useEffect,
  useMemo,
  useState,
} from "react";

import { useNavigate } from "react-router-dom";
import toast from "react-hot-toast";

import api from "../api/axios";


const defaultSummary = {
  totalScans: 0,
  phishingScans: 0,
  suspiciousScans: 0,
  safeScans: 0,
};


const escapeCsv = (value) => {
  const text = String(value ?? "");

  return `"${text.replaceAll('"', '""')}"`;
};


const ScanHistory = () => {
  const navigate = useNavigate();

  const [scans, setScans] = useState([]);
  const [summary, setSummary] =
    useState(defaultSummary);

  const [pagination, setPagination] =
    useState({
      currentPage: 1,
      totalPages: 1,
      totalScans: 0,
      resultsPerPage: 10,
    });

  const [selectedScan, setSelectedScan] =
    useState(null);

  const [selectedRows, setSelectedRows] =
    useState([]);

  const [searchTerm, setSearchTerm] =
    useState("");

  const [typeFilter, setTypeFilter] =
    useState("all");

  const [verdictFilter, setVerdictFilter] =
    useState("all");

  const [dateFilter, setDateFilter] =
    useState("all");

  const [feedback, setFeedback] = useState({
    isCorrect: true,
    correctedVerdict: "phishing",
    comment: "",
  });

  const [savingFeedback, setSavingFeedback] =
    useState(false);

  const [loading, setLoading] =
    useState(true);


  const loadHistory = async (page = 1) => {
    try {
      setLoading(true);

      const [
        historyResponse,
        dashboardResponse,
      ] = await Promise.all([
        api.get(
          `/scans/history?page=${page}&limit=10`
        ),

        api.get("/dashboard/summary"),
      ]);

      setScans(
        historyResponse.data.scans || []
      );

      setPagination(
        historyResponse.data.pagination
      );

      setSummary(
        dashboardResponse.data.summary ||
          defaultSummary
      );

      setSelectedRows([]);
    } catch (error) {
      toast.error(
        error.response?.data?.message ||
          "Unable to load scan history"
      );
    } finally {
      setLoading(false);
    }
  };


  const loadScanDetails = async (scanId) => {
    try {
      const response = await api.get(
        `/scans/${scanId}`
      );

      const scan = response.data.scan;

      setSelectedScan(scan);

      setFeedback({
        isCorrect:
          scan.analystFeedback
            ?.isCorrect ?? true,

        correctedVerdict:
          scan.analystFeedback
            ?.correctedVerdict ||
          scan.verdict ||
          "phishing",

        comment:
          scan.analystFeedback
            ?.comment || "",
      });
    } catch (error) {
      toast.error(
        error.response?.data?.message ||
          "Unable to load scan details"
      );
    }
  };


  const closeScanDetails = () => {
    setSelectedScan(null);

    setFeedback({
      isCorrect: true,
      correctedVerdict: "phishing",
      comment: "",
    });
  };


  const submitFeedback = async () => {
    if (!selectedScan) {
      return;
    }

    try {
      setSavingFeedback(true);

      const requestData = {
        isCorrect: feedback.isCorrect,
        comment: feedback.comment.trim(),
      };

      if (!feedback.isCorrect) {
        requestData.correctedVerdict =
          feedback.correctedVerdict;
      }

      const response = await api.patch(
        `/scans/${selectedScan._id}/feedback`,
        requestData
      );

      setSelectedScan((currentScan) => ({
        ...currentScan,
        analystFeedback:
          response.data.analystFeedback,
      }));

      setScans((currentScans) =>
        currentScans.map((scan) =>
          scan._id === selectedScan._id
            ? {
                ...scan,
                analystFeedback:
                  response.data
                    .analystFeedback,
              }
            : scan
        )
      );

      toast.success(
        "Detection feedback saved"
      );
    } catch (error) {
      toast.error(
        error.response?.data?.message ||
          "Unable to save feedback"
      );
    } finally {
      setSavingFeedback(false);
    }
  };


  useEffect(() => {
    loadHistory();
  }, []);


  const filteredScans = useMemo(() => {
    const normalizedSearch =
      searchTerm.trim().toLowerCase();

    const now = new Date();

    return scans.filter((scan) => {
      const target =
        scan.scanType === "email"
          ? `${scan.emailData?.subject || ""} ${
              scan.emailData?.sender || ""
            }`
          : scan.submittedUrl || "";

      const matchesSearch =
        !normalizedSearch ||
        target
          .toLowerCase()
          .includes(normalizedSearch);

      const matchesType =
        typeFilter === "all" ||
        scan.scanType === typeFilter;

      const matchesVerdict =
        verdictFilter === "all" ||
        scan.verdict === verdictFilter;

      let matchesDate = true;

      if (dateFilter !== "all") {
        const scanDate = new Date(
          scan.createdAt
        );

        const differenceInDays =
          (now - scanDate) /
          (1000 * 60 * 60 * 24);

        if (dateFilter === "today") {
          matchesDate =
            now.toDateString() ===
            scanDate.toDateString();
        }

        if (dateFilter === "7days") {
          matchesDate =
            differenceInDays <= 7;
        }

        if (dateFilter === "30days") {
          matchesDate =
            differenceInDays <= 30;
        }
      }

      return (
        matchesSearch &&
        matchesType &&
        matchesVerdict &&
        matchesDate
      );
    });
  }, [
    scans,
    searchTerm,
    typeFilter,
    verdictFilter,
    dateFilter,
  ]);


  const historyInsights = useMemo(() => {
    const indicatorCounts = {};

    scans.forEach((scan) => {
      scan.detectedIndicators?.forEach(
        (indicator) => {
          const name = indicator.category
            ?.replaceAll("_", " ");

          if (name) {
            indicatorCounts[name] =
              (indicatorCounts[name] || 0) +
              1;
          }
        }
      );
    });

    const commonIndicator =
      Object.entries(indicatorCounts).sort(
        (first, second) =>
          second[1] - first[1]
      )[0]?.[0] || "No indicators yet";

    const highestRiskScan = [...scans].sort(
      (first, second) =>
        second.riskScore -
        first.riskScore
    )[0];

    const emailScans = scans.filter(
      (scan) => scan.scanType === "email"
    ).length;

    const urlScans = scans.filter(
      (scan) => scan.scanType === "url"
    ).length;

    const reviewed = scans.filter(
      (scan) =>
        scan.analystFeedback?.reviewedAt
    ).length;

    const reviewedPercentage =
      scans.length > 0
        ? Math.round(
            (reviewed / scans.length) *
              100
          )
        : 0;

    return {
      commonIndicator,
      highestRiskScan,
      emailScans,
      urlScans,
      reviewed,
      reviewedPercentage,
    };
  }, [scans]);


  const toggleRow = (scanId) => {
    setSelectedRows((currentRows) =>
      currentRows.includes(scanId)
        ? currentRows.filter(
            (id) => id !== scanId
          )
        : [...currentRows, scanId]
    );
  };


  const toggleAllRows = () => {
    const visibleIds = filteredScans.map(
      (scan) => scan._id
    );

    const allSelected =
      visibleIds.length > 0 &&
      visibleIds.every((id) =>
        selectedRows.includes(id)
      );

    setSelectedRows(
      allSelected ? [] : visibleIds
    );
  };


  const clearFilters = () => {
    setSearchTerm("");
    setTypeFilter("all");
    setVerdictFilter("all");
    setDateFilter("all");
  };


  const exportCsv = () => {
    if (filteredScans.length === 0) {
      toast.error(
        "No scan records available to export"
      );

      return;
    }

    const headings = [
      "Type",
      "Target",
      "Verdict",
      "Risk Score",
      "Confidence",
      "Detection Method",
      "Created At",
    ];

    const rows = filteredScans.map(
      (scan) => [
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
        ).toISOString(),
      ]
    );

    const csv = [
      headings.map(escapeCsv).join(","),
      ...rows.map((row) =>
        row.map(escapeCsv).join(",")
      ),
    ].join("\n");

    const file = new Blob([csv], {
      type: "text/csv;charset=utf-8",
    });

    const downloadUrl =
      URL.createObjectURL(file);

    const link =
      document.createElement("a");

    link.href = downloadUrl;
    link.download =
      `phishguard-scan-history-${Date.now()}.csv`;

    document.body.appendChild(link);
    link.click();
    link.remove();

    URL.revokeObjectURL(downloadUrl);

    toast.success("Scan history exported");
  };


  const summaryCards = [
    {
      title: "Total scans",
      value:
        summary.totalScans ||
        pagination.totalScans ||
        0,
      icon: Mail,
      color: "blue",
      trend: "18.6%",
    },
    {
      title: "Phishing",
      value: summary.phishingScans || 0,
      icon: ShieldAlert,
      color: "red",
      trend: "12.4%",
    },
    {
      title: "Suspicious",
      value:
        summary.suspiciousScans || 0,
      icon: AlertTriangle,
      color: "yellow",
      trend: "5.2%",
    },
    {
      title: "Safe",
      value: summary.safeScans || 0,
      icon: ShieldCheck,
      color: "green",
      trend: "22.7%",
    },
  ];


  return (
    <div className="modern-history-page">
      <section className="history-page-heading">
        <div className="history-heading-icon">
          <History size={27} />
        </div>

        <div>
          <div className="history-heading-labels">
            <span className="section-label">
              SECURITY AUDIT LOG
            </span>

            <span className="live-audit-badge">
              <i />
              LIVE AUDIT LOG
            </span>
          </div>

          <h1>Scan History</h1>

          <p>
            Search and review previously analyzed
            emails, URLs, verdicts, and security
            indicators.
          </p>
        </div>

        <div className="history-heading-actions">
          <button
            type="button"
            className="history-export-button"
            onClick={exportCsv}
          >
            <Download size={16} />
            Export CSV
          </button>

          <button
            type="button"
            className="history-new-scan-button"
            onClick={() =>
              navigate("/scan/email")
            }
          >
            <Plus size={17} />
            New scan
          </button>
        </div>
      </section>


      <section className="history-statistics-grid">
        {summaryCards.map((card) => {
          const Icon = card.icon;

          return (
            <article
              className={
                `history-stat-card ${card.color}`
              }
              key={card.title}
            >
              <span
                className={
                  `history-stat-icon ${card.color}`
                }
              >
                <Icon size={22} />
              </span>

              <div>
                <span>{card.title}</span>
                <strong>{card.value}</strong>

                <small>
                  <b>↑ {card.trend}</b>
                  {" "}vs last 7 days
                </small>
              </div>

              <div className="history-mini-trend">
                <i />
                <i />
                <i />
                <i />
                <i />
              </div>
            </article>
          );
        })}
      </section>


      <section className="history-workspace">
        <div className="history-main-column">
          <div className="history-filter-bar">
            <div className="history-search">
              <Search size={17} />

              <input
                type="search"
                placeholder="Search subject, sender, or URL"
                value={searchTerm}
                onChange={(event) =>
                  setSearchTerm(
                    event.target.value
                  )
                }
              />
            </div>


            <div className="history-type-filter">
              {["all", "email", "url"].map(
                (type) => (
                  <button
                    type="button"
                    key={type}
                    className={
                      typeFilter === type
                        ? "active"
                        : ""
                    }
                    onClick={() =>
                      setTypeFilter(type)
                    }
                  >
                    {type === "all"
                      ? "All"
                      : type.toUpperCase()}
                  </button>
                )
              )}
            </div>


            <select
              className="history-select"
              value={verdictFilter}
              onChange={(event) =>
                setVerdictFilter(
                  event.target.value
                )
              }
            >
              <option value="all">
                All verdicts
              </option>
              <option value="phishing">
                Phishing
              </option>
              <option value="suspicious">
                Suspicious
              </option>
              <option value="safe">
                Safe
              </option>
            </select>


            <select
              className="history-select"
              value={dateFilter}
              onChange={(event) =>
                setDateFilter(
                  event.target.value
                )
              }
            >
              <option value="all">
                Date range
              </option>
              <option value="today">
                Today
              </option>
              <option value="7days">
                Last 7 days
              </option>
              <option value="30days">
                Last 30 days
              </option>
            </select>


            <button
              type="button"
              className="clear-history-filters"
              onClick={clearFilters}
            >
              <FilterX size={16} />
              Clear
            </button>
          </div>


          <section className="modern-history-card">
            <div className="modern-history-table-wrapper">
              <table className="modern-history-table">
                <thead>
                  <tr>
                    <th>
                      <input
                        type="checkbox"
                        checked={
                          filteredScans.length >
                            0 &&
                          filteredScans.every(
                            (scan) =>
                              selectedRows.includes(
                                scan._id
                              )
                          )
                        }
                        onChange={toggleAllRows}
                        aria-label="Select all scans"
                      />
                    </th>

                    <th>Type</th>
                    <th>Target</th>
                    <th>Verdict</th>
                    <th>Risk score</th>
                    <th>Confidence</th>
                    <th>
                      Detection method
                    </th>
                    <th>Date</th>
                    <th>Actions</th>
                  </tr>
                </thead>

                <tbody>
                  {!loading &&
                    filteredScans.map(
                      (scan) => (
                        <tr
                          key={scan._id}
                          className={
                            selectedRows.includes(
                              scan._id
                            )
                              ? "selected"
                              : ""
                          }
                        >
                          <td>
                            <input
                              type="checkbox"
                              checked={selectedRows.includes(
                                scan._id
                              )}
                              onChange={() =>
                                toggleRow(scan._id)
                              }
                              aria-label="Select scan"
                            />
                          </td>

                          <td>
                            <div
                              className={
                                `history-type-icon ${scan.scanType}`
                              }
                            >
                              {scan.scanType ===
                              "email" ? (
                                <Mail size={16} />
                              ) : (
                                <Link2 size={16} />
                              )}
                            </div>
                          </td>

                          <td>
                            <div className="history-target">
                              <strong>
                                {scan.scanType ===
                                "email"
                                  ? scan.emailData
                                      ?.subject ||
                                    "No subject"
                                  : scan.submittedUrl}
                              </strong>

                              <span>
                                {scan.scanType ===
                                "email"
                                  ? scan.emailData
                                      ?.sender ||
                                    "Unknown sender"
                                  : "URL analysis"}
                              </span>
                            </div>
                          </td>

                          <td>
                            <span
                              className={
                                `history-verdict ${scan.verdict}`
                              }
                            >
                              {scan.verdict}
                            </span>
                          </td>

                          <td>
                            <div className="history-risk">
                              <strong>
                                {scan.riskScore}
                              </strong>

                              <div>
                                <i
                                  className={
                                    scan.verdict
                                  }
                                  style={{
                                    width:
                                      `${Math.min(
                                        scan.riskScore,
                                        100
                                      )}%`,
                                  }}
                                />
                              </div>
                            </div>
                          </td>

                          <td>
                            <span className="history-confidence">
                              {scan.confidence}%
                            </span>
                          </td>

                          <td>
                            <span className="history-method">
                              {scan.detectionMethod ||
                                "Hybrid AI"}
                            </span>
                          </td>

                          <td>
                            <span className="history-date">
                              {new Date(
                                scan.createdAt
                              ).toLocaleString()}
                            </span>
                          </td>

                          <td>
                            <div className="history-row-actions">
                              <button
                                type="button"
                                className="modern-view-button"
                                onClick={() =>
                                  loadScanDetails(
                                    scan._id
                                  )
                                }
                              >
                                <Eye size={15} />
                                View
                              </button>

                              <button
                                type="button"
                                className="history-more-button"
                                aria-label="More scan actions"
                              >
                                <MoreVertical
                                  size={16}
                                />
                              </button>
                            </div>
                          </td>
                        </tr>
                      )
                    )}
                </tbody>
              </table>


              {loading && (
                <div className="modern-history-message">
                  <div className="history-loading-ring" />

                  <strong>
                    Loading audit records
                  </strong>

                  <span>
                    Synchronizing security
                    history...
                  </span>
                </div>
              )}


              {!loading &&
                filteredScans.length === 0 && (
                  <div className="modern-history-message">
                    <FileSearch size={34} />

                    <strong>
                      No matching scans
                    </strong>

                    <span>
                      Try changing or clearing the
                      active filters.
                    </span>
                  </div>
                )}
            </div>


            <div className="modern-pagination">
              <span>
                Showing{" "}
                {filteredScans.length > 0
                  ? 1
                  : 0}
                {" "}to{" "}
                {filteredScans.length} of{" "}
                {pagination.totalScans || 0}
                {" "}records
              </span>

              <div className="pagination-controls">
                <button
                  type="button"
                  disabled={
                    pagination.currentPage <= 1
                  }
                  onClick={() =>
                    loadHistory(
                      pagination.currentPage -
                        1
                    )
                  }
                  aria-label="Previous page"
                >
                  <ChevronLeft size={17} />
                </button>

                <strong>
                  {pagination.currentPage}
                </strong>

                <span>
                  of{" "}
                  {pagination.totalPages || 1}
                </span>

                <button
                  type="button"
                  disabled={
                    pagination.currentPage >=
                    pagination.totalPages
                  }
                  onClick={() =>
                    loadHistory(
                      pagination.currentPage +
                        1
                    )
                  }
                  aria-label="Next page"
                >
                  <ChevronRight size={17} />
                </button>
              </div>
            </div>
          </section>
        </div>


        <aside className="history-insights-card">
          <header>
            <Sparkles size={16} />

            <span>HISTORY INSIGHTS</span>
          </header>

          <div className="history-insight-item danger">
            <span>
              <AlertTriangle size={18} />
            </span>

            <div>
              <small>
                Most common indicator
              </small>

              <strong>
                {historyInsights
                  .commonIndicator}
              </strong>
            </div>
          </div>


          <div className="history-insight-item risk">
            <span>
              <ShieldAlert size={18} />
            </span>

            <div>
              <small>Highest-risk scan</small>

              <strong>
                {historyInsights
                  .highestRiskScan
                  ?.riskScore || 0}
                <em>/100</em>
              </strong>
            </div>
          </div>


          <div className="history-distribution">
            <span>
              EMAIL VS URL DISTRIBUTION
            </span>

            <div className="history-distribution-ring">
              <div>
                <strong>
                  {scans.length}
                </strong>
                <small>SCANS</small>
              </div>
            </div>

            <div>
              <span>
                <i className="email" />
                Email
                <strong>
                  {
                    historyInsights.emailScans
                  }
                </strong>
              </span>

              <span>
                <i className="url" />
                URL
                <strong>
                  {historyInsights.urlScans}
                </strong>
              </span>
            </div>
          </div>


          <div className="history-insight-item reviewed">
            <span>
              <UserCheck size={18} />
            </span>

            <div>
              <small>Analyst reviewed</small>

              <strong>
                {
                  historyInsights
                    .reviewedPercentage
                }
                %
              </strong>

              <p>
                {historyInsights.reviewed} of{" "}
                {scans.length} visible scans
              </p>
            </div>
          </div>
        </aside>
      </section>


      {selectedScan && (
        <div
          className="scan-modal-backdrop"
          onMouseDown={(event) => {
            if (
              event.target ===
              event.currentTarget
            ) {
              closeScanDetails();
            }
          }}
        >
          <article className="scan-modal modern-scan-modal">
            <div className="scan-modal-header">
              <div>
                <span className="panel-label">
                  COMPLETE ANALYSIS
                </span>

                <h2>Scan details</h2>
              </div>

              <button
                type="button"
                onClick={closeScanDetails}
                aria-label="Close scan details"
              >
                <X size={20} />
              </button>
            </div>


            <div className="scan-modal-content">
              <div
                className={
                  `modal-verdict ${selectedScan.verdict}`
                }
              >
                {selectedScan.verdict ===
                "safe" ? (
                  <ShieldCheck size={24} />
                ) : (
                  <AlertTriangle size={24} />
                )}

                <div>
                  <span>VERDICT</span>

                  <strong>
                    {selectedScan.verdict}
                  </strong>
                </div>

                <b>
                  {selectedScan.riskScore}
                  /100
                </b>
              </div>


              <div className="modal-information">
                <div>
                  <span>Scan type</span>
                  <strong>
                    {selectedScan.scanType}
                  </strong>
                </div>

                <div>
                  <span>Confidence</span>
                  <strong>
                    {selectedScan.confidence}%
                  </strong>
                </div>

                <div>
                  <span>Detection method</span>
                  <strong>
                    {
                      selectedScan.detectionMethod
                    }
                  </strong>
                </div>
              </div>


              {selectedScan.scanType ===
                "email" && (
                <div className="modal-email">
                  <p>
                    <span>Sender:</span>{" "}
                    {selectedScan.emailData
                      ?.sender ||
                      "Unknown sender"}
                  </p>

                  <p>
                    <span>Recipient:</span>{" "}
                    {selectedScan.emailData
                      ?.recipient ||
                      "Not provided"}
                  </p>

                  <p>
                    <span>Subject:</span>{" "}
                    {selectedScan.emailData
                      ?.subject ||
                      "No subject"}
                  </p>

                  <div>
                    {selectedScan.emailData
                      ?.body ||
                      "Email body unavailable"}
                  </div>
                </div>
              )}


              {selectedScan.scanType ===
                "url" && (
                <div className="modal-url">
                  {selectedScan.submittedUrl}
                </div>
              )}


              <div className="modal-indicators">
                <h3>Detected indicators</h3>

                {selectedScan
                  .detectedIndicators
                  ?.length > 0 ? (
                  selectedScan.detectedIndicators.map(
                    (item) => (
                      <div key={item._id}>
                        <AlertTriangle
                          size={15}
                        />

                        <span>
                          {item.indicator}
                        </span>

                        <strong>
                          +{item.weight}
                        </strong>
                      </div>
                    )
                  )
                ) : (
                  <p>
                    No indicators detected.
                  </p>
                )}
              </div>


              <div className="feedback-section">
                <div className="feedback-heading">
                  <div>
                    <span className="panel-label">
                      ANALYST REVIEW
                    </span>

                    <h3>
                      Was this detection correct?
                    </h3>
                  </div>

                  {selectedScan
                    .analystFeedback
                    ?.reviewedAt && (
                    <span className="reviewed-label">
                      REVIEWED
                    </span>
                  )}
                </div>


                <div className="feedback-options">
                  <button
                    type="button"
                    className={
                      feedback.isCorrect
                        ? "feedback-option active"
                        : "feedback-option"
                    }
                    onClick={() =>
                      setFeedback(
                        (current) => ({
                          ...current,
                          isCorrect: true,
                        })
                      )
                    }
                  >
                    Correct detection
                  </button>

                  <button
                    type="button"
                    className={
                      !feedback.isCorrect
                        ? "feedback-option active incorrect"
                        : "feedback-option"
                    }
                    onClick={() =>
                      setFeedback(
                        (current) => ({
                          ...current,
                          isCorrect: false,
                        })
                      )
                    }
                  >
                    Incorrect detection
                  </button>
                </div>


                {!feedback.isCorrect && (
                  <label className="input-group">
                    <span>Correct verdict</span>

                    <select
                      className="feedback-select"
                      value={
                        feedback.correctedVerdict
                      }
                      onChange={(event) =>
                        setFeedback(
                          (current) => ({
                            ...current,
                            correctedVerdict:
                              event.target
                                .value,
                          })
                        )
                      }
                    >
                      <option value="safe">
                        Safe
                      </option>

                      <option value="suspicious">
                        Suspicious
                      </option>

                      <option value="phishing">
                        Phishing
                      </option>
                    </select>
                  </label>
                )}


                <label className="input-group">
                  <span>Review comment</span>

                  <textarea
                    className="feedback-comment"
                    rows={3}
                    maxLength={500}
                    placeholder="Explain why this classification is correct or incorrect..."
                    value={feedback.comment}
                    onChange={(event) =>
                      setFeedback(
                        (current) => ({
                          ...current,
                          comment:
                            event.target.value,
                        })
                      )
                    }
                  />
                </label>


                <button
                  type="button"
                  className="primary-button feedback-submit"
                  disabled={savingFeedback}
                  onClick={submitFeedback}
                >
                  {savingFeedback
                    ? "SAVING REVIEW..."
                    : "SAVE ANALYST REVIEW"}
                </button>
              </div>
            </div>
          </article>
        </div>
      )}
    </div>
  );
};


export default ScanHistory;