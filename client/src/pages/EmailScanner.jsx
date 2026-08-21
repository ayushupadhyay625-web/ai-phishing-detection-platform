import {
  AlertTriangle,
  AtSign,
  BrainCircuit,
  CheckCircle2,
  Clock3,
  Cpu,
  Download,
  FileText,
  Fingerprint,
  Link2,
  LockKeyhole,
  Mail,
  MailWarning,
  RotateCcw,
  Search,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  UserRound,
} from "lucide-react";

import { useState } from "react";
import toast from "react-hot-toast";

import api from "../api/axios";


const emptyEmail = {
  sender: "",
  recipient: "",
  subject: "",
  body: "",
};


const sampleEmail = {
  sender: "security@secure-login-verification.com",
  recipient: "employee@company.com",
  subject:
    "Urgent: Verify Your Account to Avoid Suspension",
  body: `Dear Valued Customer,

We noticed unusual activity on your account and have temporarily restricted access.

To restore full access, please verify your account immediately using the link below:

http://192.168.1.10/login/verify-account

This link will expire in 24 hours. Failure to verify your account may result in permanent suspension.

Thank you,
Account Security Team`,
};


const formatCategory = (category = "") => {
  return category
    .replaceAll("_", " ")
    .replace(/\b\w/g, (letter) =>
      letter.toUpperCase()
    );
};


const getIndicatorSeverity = (weight = 0) => {
  if (weight >= 25) {
    return "high";
  }

  if (weight >= 10) {
    return "medium";
  }

  return "low";
};


const getIndicatorIcon = (category = "") => {
  const normalizedCategory =
    category.toLowerCase();

  if (normalizedCategory.includes("url")) {
    return Link2;
  }

  if (
    normalizedCategory.includes("sender") ||
    normalizedCategory.includes("domain")
  ) {
    return AtSign;
  }

  if (
    normalizedCategory.includes("credential")
  ) {
    return LockKeyhole;
  }

  return AlertTriangle;
};


const EmailScanner = () => {
  const [emailData, setEmailData] =
    useState(emptyEmail);

  const [result, setResult] =
    useState(null);

  const [scanning, setScanning] =
    useState(false);


  const handleChange = (event) => {
    const {
      name,
      value,
    } = event.target;

    setEmailData((current) => ({
      ...current,
      [name]: value,
    }));
  };


  const handleScan = async (event) => {
    event.preventDefault();

    if (!emailData.body.trim()) {
      toast.error(
        "Please paste the email content"
      );

      return;
    }

    try {
      setScanning(true);
      setResult(null);

      const response = await api.post(
        "/scans/email",
        emailData
      );

      setResult(response.data.scan);

      toast.success(
        "Email analysis completed"
      );
    } catch (error) {
      toast.error(
        error.response?.data?.message ||
          "Email analysis failed"
      );
    } finally {
      setScanning(false);
    }
  };


  const clearScanner = () => {
    setEmailData(emptyEmail);
    setResult(null);
  };


  const loadSampleEmail = () => {
    setEmailData(sampleEmail);
    setResult(null);

    toast.success("Sample email loaded");
  };


  const downloadReport = () => {
    if (!result) {
      return;
    }

    const report = {
      generatedAt: new Date().toISOString(),
      email: emailData,
      analysis: result,
    };

    const file = new Blob(
      [JSON.stringify(report, null, 2)],
      {
        type: "application/json",
      }
    );

    const downloadUrl =
      URL.createObjectURL(file);

    const link =
      document.createElement("a");

    link.href = downloadUrl;
    link.download =
      `phishguard-email-report-${result._id || Date.now()}.json`;

    document.body.appendChild(link);
    link.click();
    link.remove();

    URL.revokeObjectURL(downloadUrl);

    toast.success("Security report downloaded");
  };


  const verdict =
    result?.verdict || "unknown";

  const riskScore =
    Number(result?.riskScore) || 0;

  const confidence =
    Number(result?.confidence) || 0;

  const ruleScore =
    Number(result?.ruleRiskScore) || 0;

  const mlScore =
    Number(result?.mlRiskScore) || 0;

  const indicators =
    result?.detectedIndicators || [];

  const extractedUrls =
    result?.extractedUrls || [];


  return (
    <div className="modern-email-scanner">
      <section className="email-page-heading">
        <div className="email-heading-icon">
          <MailWarning size={27} />
        </div>

        <div>
          <div className="email-heading-labels">
            <span className="section-label">
              EMAIL THREAT ANALYSIS
            </span>

            <span className="live-analysis-badge">
              <i />
              LIVE ANALYSIS
            </span>
          </div>

          <h1>Phishing Email Scanner</h1>

          <p>
            Analyze message content, sender
            identity, urgency signals, and
            embedded URLs with explainable AI.
          </p>
        </div>

        <button
          type="button"
          className="sample-email-button"
          onClick={loadSampleEmail}
        >
          <Sparkles size={16} />
          Load sample
        </button>
      </section>


      <section className="modern-email-grid">
        <article className="email-glass-card email-input-card">
          <header className="email-card-header">
            <div>
              <span className="email-card-icon blue">
                <Mail size={18} />
              </span>

              <div>
                <span className="panel-label">
                  EMAIL INPUT
                </span>

                <h2>Message information</h2>
              </div>
            </div>

            <span className="encrypted-pill">
              <LockKeyhole size={13} />
              Encrypted
            </span>
          </header>


          <form
            className="modern-email-form"
            onSubmit={handleScan}
          >
            <div className="modern-two-fields">
              <label className="modern-field">
                <span>Sender address</span>

                <div className="modern-field-wrapper">
                  <AtSign size={17} />

                  <input
                    type="text"
                    name="sender"
                    placeholder="security@example.com"
                    value={emailData.sender}
                    onChange={handleChange}
                  />
                </div>
              </label>


              <label className="modern-field">
                <span>Recipient</span>

                <div className="modern-field-wrapper">
                  <UserRound size={17} />

                  <input
                    type="email"
                    name="recipient"
                    placeholder="employee@company.com"
                    value={emailData.recipient}
                    onChange={handleChange}
                  />
                </div>
              </label>
            </div>


            <label className="modern-field">
              <span>Subject line</span>

              <div className="modern-field-wrapper">
                <FileText size={17} />

                <input
                  type="text"
                  name="subject"
                  placeholder="Urgent: verify your account"
                  value={emailData.subject}
                  onChange={handleChange}
                />
              </div>
            </label>


            <label className="modern-field">
              <span>Email body</span>

              <div className="modern-textarea-wrapper">
                <textarea
                  name="body"
                  rows={15}
                  placeholder="Paste the complete email content here..."
                  value={emailData.body}
                  onChange={handleChange}
                  required
                />

                <span className="character-counter">
                  {emailData.body.length.toLocaleString()}
                  {" "}characters
                </span>
              </div>
            </label>


            <div className="email-analysis-summary">
              <div>
                <ShieldCheck size={16} />

                <span>
                  Content is processed securely
                  and used only for threat
                  analysis.
                </span>
              </div>

              <span>
                {emailData.body.trim()
                  ? "Ready to analyze"
                  : "Waiting for content"}
              </span>
            </div>


            <div className="modern-scanner-actions">
              <button
                type="submit"
                className="modern-analyze-button"
                disabled={scanning}
              >
                {scanning ? (
                  <>
                    <span className="button-spinner" />
                    Running AI analysis...
                  </>
                ) : (
                  <>
                    <Search size={18} />
                    Analyze email
                  </>
                )}
              </button>

              <button
                type="button"
                className="modern-clear-button"
                onClick={clearScanner}
                disabled={scanning}
              >
                <RotateCcw size={17} />
                Clear
              </button>
            </div>
          </form>
        </article>


        <article className="email-glass-card email-result-card">
          <header className="email-card-header">
            <div>
              <span className="email-card-icon violet">
                <ShieldAlert size={18} />
              </span>

              <div>
                <span className="panel-label">
                  ANALYSIS RESULT
                </span>

                <h2>Threat assessment</h2>
              </div>
            </div>

            {result && (
              <button
                type="button"
                className="download-analysis-button"
                onClick={downloadReport}
              >
                <Download size={15} />
                Download report
              </button>
            )}
          </header>


          {!result ? (
            <div className="modern-result-empty">
              <div className="empty-scanner-visual">
                <div className="empty-orbit orbit-a" />
                <div className="empty-orbit orbit-b" />

                <Search size={34} />
              </div>

              <h3>Ready for analysis</h3>

              <p>
                Submit an email to generate an
                explainable security assessment.
              </p>

              <div className="empty-analysis-steps">
                <span>Content inspection</span>
                <span>URL intelligence</span>
                <span>ML classification</span>
              </div>
            </div>
          ) : (
            <div className="advanced-analysis-result">
              <section className="result-overview">
                <div
                  className={
                    `email-risk-ring ${verdict}`
                  }
                  style={{
                    "--email-risk":
                      `${riskScore * 3.6}deg`,
                  }}
                >
                  <div>
                    <strong>{riskScore}</strong>
                    <span>/100</span>
                    <small>RISK SCORE</small>
                  </div>
                </div>


                <div className="verdict-details">
                  <span>VERDICT</span>

                  <h3 className={verdict}>
                    {verdict}
                  </h3>

                  <span>CONFIDENCE</span>

                  <strong>{confidence}%</strong>

                  <small
                    className={
                      confidence >= 80
                        ? "high"
                        : "moderate"
                    }
                  >
                    {confidence >= 80
                      ? "High confidence"
                      : "Moderate confidence"}
                  </small>
                </div>


                <div className="hybrid-breakdown">
                  <span className="result-section-title">
                    HYBRID SCORE BREAKDOWN
                  </span>

                  <div className="hybrid-score-row rules">
                    <span className="hybrid-icon">
                      <Cpu size={16} />
                    </span>

                    <div>
                      <span>Rules engine</span>

                      <div className="hybrid-progress">
                        <i
                          style={{
                            width:
                              `${Math.min(
                                ruleScore,
                                100
                              )}%`,
                          }}
                        />
                      </div>
                    </div>

                    <strong>{ruleScore}%</strong>
                  </div>


                  <div className="hybrid-score-row ml">
                    <span className="hybrid-icon">
                      <BrainCircuit size={16} />
                    </span>

                    <div>
                      <span>ML model</span>

                      <div className="hybrid-progress">
                        <i
                          style={{
                            width:
                              `${Math.min(
                                mlScore,
                                100
                              )}%`,
                          }}
                        />
                      </div>
                    </div>

                    <strong>{mlScore}%</strong>
                  </div>
                </div>
              </section>


              <section className="threat-severity-section">
                <div>
                  <span className="result-section-title">
                    THREAT SEVERITY
                  </span>

                  <strong>{riskScore}/100</strong>
                </div>

                <div className="severity-track">
                  <i
                    style={{
                      left:
                        `calc(${Math.min(
                          riskScore,
                          100
                        )}% - 6px)`,
                    }}
                  />
                </div>

                <div className="severity-labels">
                  <span>Low</span>
                  <span>Medium</span>
                  <span>High</span>
                  <span>Critical</span>
                </div>
              </section>


              <section className="email-result-details">
                <div className="advanced-indicators">
                  <div className="result-subheading">
                    <span>
                      DETECTED INDICATORS
                    </span>

                    <strong>
                      {indicators.length}
                    </strong>
                  </div>

                  {indicators.length > 0 ? (
                    <div className="advanced-indicator-list">
                      {indicators.map(
                        (indicator, index) => {
                          const severity =
                            getIndicatorSeverity(
                              indicator.weight
                            );

                          const IndicatorIcon =
                            getIndicatorIcon(
                              indicator.category
                            );

                          return (
                            <div
                              className={
                                `advanced-indicator ${severity}`
                              }
                              key={
                                indicator._id ||
                                `${indicator.category}-${index}`
                              }
                            >
                              <span className="indicator-symbol">
                                <IndicatorIcon
                                  size={16}
                                />
                              </span>

                              <div>
                                <strong>
                                  {
                                    indicator.indicator
                                  }
                                </strong>

                                <small>
                                  {formatCategory(
                                    indicator.category
                                  )}
                                </small>
                              </div>

                              <span
                                className={
                                  `indicator-severity ${severity}`
                                }
                              >
                                {severity}
                              </span>

                              <b>
                                +{indicator.weight}
                              </b>
                            </div>
                          );
                        }
                      )}
                    </div>
                  ) : (
                    <div className="advanced-safe-message">
                      <CheckCircle2 size={19} />

                      <div>
                        <strong>
                          No major threats detected
                        </strong>

                        <span>
                          The analyzed content did
                          not trigger phishing
                          indicators.
                        </span>
                      </div>
                    </div>
                  )}
                </div>


                <aside className="url-intelligence-card">
                  <div className="result-subheading">
                    <span>
                      EXTRACTED URL INTELLIGENCE
                    </span>

                    <Link2 size={16} />
                  </div>

                  {extractedUrls.length > 0 ? (
                    <div className="url-intelligence-list">
                      {extractedUrls.map(
                        (url, index) => (
                          <div
                            className="extracted-url-item"
                            key={`${url}-${index}`}
                          >
                            <Link2 size={16} />

                            <span>{url}</span>
                          </div>
                        )
                      )}

                      <div className="url-detail-row">
                        <span>URL status</span>

                        <strong className={verdict}>
                          {verdict}
                        </strong>
                      </div>

                      <div className="url-detail-row">
                        <span>URLs detected</span>

                        <strong>
                          {extractedUrls.length}
                        </strong>
                      </div>
                    </div>
                  ) : (
                    <div className="no-url-message">
                      <ShieldCheck size={25} />

                      <span>
                        No embedded URLs detected
                      </span>
                    </div>
                  )}
                </aside>
              </section>


              <footer className="analysis-metadata">
                <div>
                  <span className="metadata-icon">
                    <BrainCircuit size={17} />
                  </span>

                  <span>
                    <small>DETECTION ENGINE</small>
                    <strong>
                      {result.detectionMethod ||
                        "Hybrid ML + Rule Fusion"}
                    </strong>
                  </span>
                </div>

                <div>
                  <span className="metadata-icon">
                    <Clock3 size={17} />
                  </span>

                  <span>
                    <small>ANALYSIS TIME</small>
                    <strong>
                      {new Date(
                        result.createdAt ||
                          Date.now()
                      ).toLocaleString()}
                    </strong>
                  </span>
                </div>

                <div>
                  <span className="metadata-icon">
                    <Fingerprint size={17} />
                  </span>

                  <span>
                    <small>SCAN ID</small>
                    <strong>
                      {result._id
                        ? result._id
                            .slice(-10)
                            .toUpperCase()
                        : "AVAILABLE"}
                    </strong>
                  </span>
                </div>
              </footer>
            </div>
          )}
        </article>
      </section>
    </div>
  );
};


export default EmailScanner;