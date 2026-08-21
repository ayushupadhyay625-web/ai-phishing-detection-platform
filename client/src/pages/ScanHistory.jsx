import {
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
  Eye,
  History,
  Link2,
  Mail,
  ShieldCheck,
} from "lucide-react";

import {
  useEffect,
  useState,
} from "react";

import toast from "react-hot-toast";

import api from "../api/axios";


const ScanHistory = () => {
  const [scans, setScans] = useState([]);

  const [pagination, setPagination] =
    useState({
      currentPage: 1,
      totalPages: 1,
      totalScans: 0,
    });

  const [selectedScan, setSelectedScan] =
    useState(null);

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

      const response = await api.get(
        `/scans/history?page=${page}&limit=10`
      );

      setScans(response.data.scans);

      setPagination(
        response.data.pagination
      );
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


  return (
    <>
      <section className="page-heading">
        <div>
          <p className="section-label">
            SECURITY AUDIT LOG
          </p>

          <h1>Scan History</h1>

          <p>
            Review previously analyzed emails,
            URLs, verdicts, and risk indicators.
          </p>
        </div>

        <div className="history-count">
          <History size={18} />

          <span>
            {pagination.totalScans} records
          </span>
        </div>
      </section>


      <section className="panel history-panel">
        <div className="history-table-wrapper">
          <table className="history-table">
            <thead>
              <tr>
                <th>Type</th>

                <th>Target</th>

                <th>Verdict</th>

                <th>Risk</th>

                <th>Confidence</th>

                <th>Date</th>

                <th>Details</th>
              </tr>
            </thead>

            <tbody>
              {!loading &&
                scans.map((scan) => (
                  <tr key={scan._id}>
                    <td>
                      <div className="table-type">
                        {scan.scanType ===
                        "email" ? (
                          <Mail size={16} />
                        ) : (
                          <Link2 size={16} />
                        )}

                        {scan.scanType}
                      </div>
                    </td>

                    <td>
                      <div className="scan-target">
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
                          `verdict-badge ${scan.verdict}`
                        }
                      >
                        {scan.verdict}
                      </span>
                    </td>

                    <td>
                      <strong className="table-score">
                        {scan.riskScore}
                      </strong>
                    </td>

                    <td>
                      {scan.confidence}%
                    </td>

                    <td>
                      {new Date(
                        scan.createdAt
                      ).toLocaleString()}
                    </td>

                    <td>
                      <button
                        type="button"
                        className="view-scan-button"
                        onClick={() =>
                          loadScanDetails(
                            scan._id
                          )
                        }
                      >
                        <Eye size={16} />

                        View
                      </button>
                    </td>
                  </tr>
                ))}
            </tbody>
          </table>


          {loading && (
            <div className="history-message">
              Loading scan records...
            </div>
          )}


          {!loading &&
            scans.length === 0 && (
              <div className="history-message">
                <ShieldCheck size={34} />

                No scans have been recorded.
              </div>
            )}
        </div>


        <div className="pagination">
          <span>
            Page {pagination.currentPage} of{" "}
            {pagination.totalPages || 1}
          </span>

          <div>
            <button
              type="button"
              disabled={
                pagination.currentPage <= 1
              }
              onClick={() =>
                loadHistory(
                  pagination.currentPage - 1
                )
              }
            >
              <ChevronLeft size={17} />

              Previous
            </button>

            <button
              type="button"
              disabled={
                pagination.currentPage >=
                pagination.totalPages
              }
              onClick={() =>
                loadHistory(
                  pagination.currentPage + 1
                )
              }
            >
              Next

              <ChevronRight size={17} />
            </button>
          </div>
        </div>
      </section>


      {selectedScan && (
        <div className="scan-modal-backdrop">
          <article className="scan-modal">
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
                ×
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
                  <span>
                    Detection method
                  </span>

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
                      Was this detection
                      correct?
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
                    <span>
                      Correct verdict
                    </span>

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
                  <span>
                    Review comment
                  </span>

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
                            event.target
                              .value,
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
    </>
  );
};


export default ScanHistory;