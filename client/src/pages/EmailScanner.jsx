import {
  AlertTriangle,
  CheckCircle2,
  MailWarning,
  Search,
  ShieldAlert,
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


  const getVerdictIcon = () => {
    if (result?.verdict === "phishing") {
      return <ShieldAlert size={30} />;
    }

    if (result?.verdict === "suspicious") {
      return <AlertTriangle size={30} />;
    }

    return <CheckCircle2 size={30} />;
  };


  return (
    <>
      <section className="page-heading">
        <div>
          <p className="section-label">
            EMAIL THREAT ANALYSIS
          </p>

          <h1>Phishing Email Scanner</h1>

          <p>
            Analyze email content, sender
            information, urgency signals, and
            embedded URLs.
          </p>
        </div>
      </section>


      <section className="scanner-grid">
        <article className="panel scanner-panel">
          <div className="panel-header">
            <div>
              <span className="panel-label">
                EMAIL INPUT
              </span>

              <h2>Message information</h2>
            </div>

            <MailWarning size={21} />
          </div>


          <form
            className="scanner-form"
            onSubmit={handleScan}
          >
            <div className="two-column-fields">
              <label className="input-group">
                <span>Sender</span>

                <div className="input-wrapper">
                  <input
                    type="text"
                    name="sender"
                    placeholder="security@example.com"
                    value={emailData.sender}
                    onChange={handleChange}
                  />
                </div>
              </label>


              <label className="input-group">
                <span>Recipient</span>

                <div className="input-wrapper">
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


            <label className="input-group">
              <span>Subject</span>

              <div className="input-wrapper">
                <input
                  type="text"
                  name="subject"
                  placeholder="Urgent: verify your account"
                  value={emailData.subject}
                  onChange={handleChange}
                />
              </div>
            </label>


            <label className="input-group">
              <span>Email body</span>

              <textarea
                className="scanner-textarea"
                name="body"
                rows={12}
                placeholder="Paste the complete email content here..."
                value={emailData.body}
                onChange={handleChange}
                required
              />
            </label>


            <div className="scanner-actions">
              <button
                type="submit"
                className="primary-button scan-button"
                disabled={scanning}
              >
                <Search size={17} />

                {scanning
                  ? "ANALYZING EMAIL..."
                  : "ANALYZE EMAIL"}
              </button>

              <button
                type="button"
                className="secondary-button"
                onClick={clearScanner}
              >
                Clear
              </button>
            </div>
          </form>
        </article>


        <article className="panel result-panel">
          <div className="panel-header">
            <div>
              <span className="panel-label">
                ANALYSIS RESULT
              </span>

              <h2>Threat assessment</h2>
            </div>

            <ShieldAlert size={21} />
          </div>


          {!result ? (
            <div className="empty-state result-empty">
              <Search size={40} />

              <p>
                Submit an email to view its
                security assessment.
              </p>
            </div>
          ) : (
            <div className="analysis-result">
              <div
                className={
                  `verdict-summary ${result.verdict}`
                }
              >
                <div className="verdict-icon">
                  {getVerdictIcon()}
                </div>

                <div>
                  <span>VERDICT</span>

                  <h3>
                    {result.verdict}
                  </h3>
                </div>

                <div className="risk-score">
                  <strong>
                    {result.riskScore}
                  </strong>

                  <span>/100 RISK</span>
                </div>
              </div>


              <div className="confidence-row">
                <span>
                  Detection confidence
                </span>

                <strong>
                  {result.confidence}%
                </strong>
              </div>
<div className="hybrid-score-panel">
  <div className="hybrid-score-heading">
    <span>HYBRID RISK CALCULATION</span>

    <strong>
      70% RULES + 30% ML
    </strong>
  </div>


  <div className="score-comparison">
    <div>
      <span>Rule engine</span>

      <strong>
        {result.ruleRiskScore || 0}
      </strong>

      <div className="score-bar">
        <i
          style={{
            width:
              `${result.ruleRiskScore || 0}%`,
          }}
        />
      </div>
    </div>


    <div>
      <span>ML probability</span>

      <strong>
        {result.mlRiskScore || 0}%
      </strong>

      <div className="score-bar ml">
        <i
          style={{
            width:
              `${result.mlRiskScore || 0}%`,
          }}
        />
      </div>
    </div>
  </div>


  <div className="model-prediction">
    <span>ML prediction</span>

    <strong
      className={
        result.mlAnalysis?.prediction ||
        "unavailable"
      }
    >
      {result.mlAnalysis?.prediction ||
        "unavailable"}
    </strong>
  </div>
</div>

              <div className="indicator-section">
                <div className="indicator-heading">
                  <span>
                    DETECTED INDICATORS
                  </span>

                  <strong>
                    {
                      result
                        .detectedIndicators
                        .length
                    }
                  </strong>
                </div>

                <div className="indicator-list">
                  {result.detectedIndicators
                    .length > 0 ? (
                    result.detectedIndicators.map(
                      (item) => (
                        <div
                          className="indicator-item"
                          key={item._id}
                        >
                          <AlertTriangle
                            size={16}
                          />

                          <div>
                            <strong>
                              {item.indicator}
                            </strong>

                            <span>
                              {item.category
                                .replace(
                                  "_",
                                  " "
                                )}
                            </span>
                          </div>

                          <b>
                            +{item.weight}
                          </b>
                        </div>
                      )
                    )
                  ) : (
                    <div className="safe-message">
                      <CheckCircle2
                        size={18}
                      />

                      No major phishing
                      indicators detected.
                    </div>
                  )}
                </div>
              </div>


              <div className="method-label">
                Detection method:
                <strong>
                  {result.detectionMethod}
                </strong>
              </div>
            </div>
          )}
        </article>
      </section>
    </>
  );
};


export default EmailScanner;