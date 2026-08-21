import {
  AlertTriangle,
  BrainCircuit,
  CheckCircle2,
  Clipboard,
  Download,
  ExternalLink,
  FileSearch,
  Folder,
  Globe2,
  Link2,
  LockKeyhole,
  Network,
  RotateCcw,
  Route,
  Search,
  Server,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Tag,
} from "lucide-react";

import { useMemo, useState } from "react";
import toast from "react-hot-toast";

import api from "../api/axios";


const safeExample =
  "https://www.google.com";

const suspiciousExample =
  "http://192.168.1.10/login/verify-account";


const parseUrlDetails = (value = "") => {
  try {
    const parsedUrl = new URL(value);

    const isIpAddress =
      /^(\d{1,3}\.){3}\d{1,3}$/.test(
        parsedUrl.hostname
      );

    return {
      protocol:
        parsedUrl.protocol
          .replace(":", "")
          .toUpperCase() || "Unknown",
      hostname:
        parsedUrl.hostname || "Unknown",
      path:
        `${parsedUrl.pathname}${parsedUrl.search}` ||
        "/",
      secure:
        parsedUrl.protocol === "https:",
      domainType: isIpAddress
        ? "IP address"
        : "Domain name",
      port:
        parsedUrl.port || "Default",
    };
  } catch {
    return {
      protocol: "Unknown",
      hostname: "Unable to parse",
      path: "Unknown",
      secure: false,
      domainType: "Unknown",
      port: "Unknown",
    };
  }
};


const formatCategory = (category = "") => {
  return category
    .replaceAll("_", " ")
    .replace(/\b\w/g, (letter) =>
      letter.toUpperCase()
    );
};


const getSignalSeverity = (weight = 0) => {
  if (weight >= 25) {
    return "high";
  }

  if (weight >= 10) {
    return "medium";
  }

  return "low";
};


const getSignalIcon = (message = "") => {
  const normalized = message.toLowerCase();

  if (
    normalized.includes("ip address") ||
    normalized.includes("domain")
  ) {
    return Server;
  }

  if (
    normalized.includes("https") ||
    normalized.includes("secure")
  ) {
    return LockKeyhole;
  }

  if (
    normalized.includes("login") ||
    normalized.includes("terminology")
  ) {
    return Tag;
  }

  if (normalized.includes("redirect")) {
    return Route;
  }

  return AlertTriangle;
};


const URLScanner = () => {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [scanning, setScanning] =
    useState(false);


  const handleScan = async (event) => {
    event.preventDefault();

    if (!url.trim()) {
      toast.error("Please enter a URL");
      return;
    }

    try {
      setScanning(true);
      setResult(null);

      const response = await api.post(
        "/scans/url",
        {
          url: url.trim(),
        }
      );

      setResult(response.data.scan);

      toast.success("URL analysis completed");
    } catch (error) {
      toast.error(
        error.response?.data?.message ||
          "URL analysis failed"
      );
    } finally {
      setScanning(false);
    }
  };


  const clearScanner = () => {
    setUrl("");
    setResult(null);
  };


  const loadExample = (
    exampleUrl,
    message
  ) => {
    setUrl(exampleUrl);
    setResult(null);
    toast.success(message);
  };


  const copyAnalysis = async () => {
    if (!result) {
      return;
    }

    try {
      await navigator.clipboard.writeText(
        JSON.stringify(result, null, 2)
      );

      toast.success(
        "Analysis copied to clipboard"
      );
    } catch {
      toast.error("Unable to copy analysis");
    }
  };


  const downloadReport = () => {
    if (!result) {
      return;
    }

    const report = {
      generatedAt: new Date().toISOString(),
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
      `phishguard-url-report-${result._id || Date.now()}.json`;

    document.body.appendChild(link);
    link.click();
    link.remove();

    URL.revokeObjectURL(downloadUrl);

    toast.success("URL report downloaded");
  };


  const verdict =
    result?.verdict || "unknown";

  const riskScore =
    Number(result?.riskScore) || 0;

  const confidence =
    Number(result?.confidence) || 0;

  const indicators =
    result?.detectedIndicators || [];


  const parsedUrl = useMemo(
    () =>
      parseUrlDetails(
        result?.submittedUrl || url
      ),
    [result?.submittedUrl, url]
  );


  const explanation =
    indicators.length > 0
      ? indicators
          .map((item) => item.indicator)
          .join(". ")
      : "No common malicious URL characteristics were detected by the current analysis engine.";


  const recommendation =
    verdict === "phishing"
      ? "Do not visit this URL or enter personal, authentication, or payment information."
      : verdict === "suspicious"
        ? "Avoid opening this URL until its ownership and destination have been independently verified."
        : "No common threats were detected, but continue using normal browsing precautions.";


  return (
    <div className="modern-url-scanner">
      <section className="url-page-heading">
        <div className="url-heading-icon">
          <Link2 size={28} />
        </div>

        <div>
          <div className="url-heading-labels">
            <span className="section-label">
              URL THREAT INTELLIGENCE
            </span>

            <span className="live-url-badge">
              <i />
              LIVE URL INTELLIGENCE
            </span>
          </div>

          <h1>Malicious URL Scanner</h1>

          <p>
            Detect spoofing, insecure protocols,
            suspicious paths, and phishing
            patterns with explainable analysis.
          </p>
        </div>
      </section>


      <section className="url-investigation-card">
        <form
          className="modern-url-form"
          onSubmit={handleScan}
        >
          <label>
            Enter URL to analyze
          </label>

          <div className="modern-url-input-row">
            <div className="modern-url-input">
              <Link2 size={20} />

              <input
                type="text"
                placeholder="https://example.com/account/verify"
                value={url}
                onChange={(event) =>
                  setUrl(event.target.value)
                }
                required
              />
            </div>

            <button
              type="submit"
              className="modern-url-analyze-button"
              disabled={scanning}
            >
              {scanning ? (
                <>
                  <span className="button-spinner" />
                  Analyzing URL...
                </>
              ) : (
                <>
                  <Sparkles size={18} />
                  Analyze URL
                </>
              )}
            </button>
          </div>


          <div className="url-form-footer">
            <div className="modern-url-examples">
              <span>QUICK EXAMPLES:</span>

              <button
                type="button"
                className="safe"
                onClick={() =>
                  loadExample(
                    safeExample,
                    "Safe example loaded"
                  )
                }
              >
                <ShieldCheck size={14} />
                Safe example
              </button>

              <button
                type="button"
                className="suspicious"
                onClick={() =>
                  loadExample(
                    suspiciousExample,
                    "Suspicious example loaded"
                  )
                }
              >
                <AlertTriangle size={14} />
                Suspicious example
              </button>

              <button
                type="button"
                onClick={clearScanner}
              >
                <RotateCcw size={14} />
                Clear
              </button>
            </div>

            <div className="url-sandbox-note">
              <LockKeyhole size={14} />

              All scans are private and executed
              in a secure analysis environment.
            </div>
          </div>
        </form>
      </section>


      {!result ? (
        <section className="url-awaiting-card">
          <div className="url-awaiting-visual">
            <div className="url-radar-ring ring-one" />
            <div className="url-radar-ring ring-two" />
            <div className="url-radar-line" />

            <Search size={35} />
          </div>

          <h2>Awaiting URL analysis</h2>

          <p>
            Enter a link above to calculate its
            threat score and inspect its
            explainable risk indicators.
          </p>

          <div className="url-awaiting-features">
            <span>Protocol inspection</span>
            <span>Lexical analysis</span>
            <span>Threat scoring</span>
          </div>
        </section>
      ) : (
        <div className="advanced-url-result">
          <section className="url-verdict-card">
            <div
              className={
                `url-risk-ring ${verdict}`
              }
              style={{
                "--url-risk":
                  `${riskScore * 3.6}deg`,
              }}
            >
              <div>
                <strong>{riskScore}</strong>
                <span>/100</span>
              </div>
            </div>


            <div className="url-verdict-details">
              <span>VERDICT</span>

              <h2 className={verdict}>
                {verdict}
              </h2>

              <div className="url-confidence-meter">
                <span>
                  Confidence:
                  <strong>
                    {" "}{confidence}%
                  </strong>
                </span>

                <div>
                  <i
                    style={{
                      width:
                        `${Math.min(
                          confidence,
                          100
                        )}%`,
                    }}
                  />
                </div>
              </div>
            </div>


            <div className="url-severity-block">
              <div>
                <span>THREAT SEVERITY</span>
                <strong>{riskScore}/100</strong>
              </div>

              <div className="url-severity-track">
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

              <div className="url-severity-labels">
                <span>Low</span>
                <span>Medium</span>
                <span>High</span>
                <span>Critical</span>
              </div>
            </div>


            <div className="url-result-actions">
              <button
                type="button"
                onClick={copyAnalysis}
              >
                <Clipboard size={16} />
                Copy analysis
              </button>

              <button
                type="button"
                onClick={downloadReport}
              >
                <Download size={16} />
                Download report
              </button>
            </div>
          </section>


          <section className="url-analysis-grid">
            <article className="url-analysis-card url-overview-card">
              <header>
                <div>
                  <Globe2 size={17} />
                  <h3>URL overview</h3>
                </div>

                <ExternalLink size={15} />
              </header>

              <div className="url-overview-list">
                <div>
                  <span>
                    <Globe2 size={15} />
                    Protocol
                  </span>

                  <strong
                    className={
                      parsedUrl.secure
                        ? "safe"
                        : "danger"
                    }
                  >
                    {parsedUrl.protocol}
                  </strong>
                </div>

                <div>
                  <span>
                    <Server size={15} />
                    Host / IP
                  </span>

                  <strong>
                    {parsedUrl.hostname}
                  </strong>
                </div>

                <div>
                  <span>
                    <Folder size={15} />
                    Path
                  </span>

                  <strong>
                    {parsedUrl.path}
                  </strong>
                </div>

                <div>
                  <span>
                    <LockKeyhole size={15} />
                    HTTPS status
                  </span>

                  <strong
                    className={
                      parsedUrl.secure
                        ? "safe"
                        : "danger"
                    }
                  >
                    {parsedUrl.secure
                      ? "Secure"
                      : "Not secure"}
                  </strong>
                </div>

                <div>
                  <span>
                    <Tag size={15} />
                    Domain type
                  </span>

                  <strong>
                    {parsedUrl.domainType}
                  </strong>
                </div>

                <div>
                  <span>
                    <Network size={15} />
                    Port
                  </span>

                  <strong>
                    {parsedUrl.port}
                  </strong>
                </div>
              </div>
            </article>


            <article className="url-analysis-card risk-signals-card">
              <header>
                <div>
                  <ShieldAlert size={17} />
                  <h3>Detected risk signals</h3>
                </div>

                <span className="signal-count">
                  {indicators.length}
                </span>
              </header>

              {indicators.length > 0 ? (
                <div className="modern-url-signals">
                  {indicators.map(
                    (indicator, index) => {
                      const severity =
                        getSignalSeverity(
                          indicator.weight
                        );

                      const SignalIcon =
                        getSignalIcon(
                          indicator.indicator
                        );

                      return (
                        <div
                          className={
                            `modern-url-signal ${severity}`
                          }
                          key={
                            indicator._id ||
                            `${indicator.category}-${index}`
                          }
                        >
                          <span>
                            <SignalIcon size={17} />
                          </span>

                          <div>
                            <strong>
                              {indicator.indicator}
                            </strong>

                            <small>
                              {formatCategory(
                                indicator.category
                              )}
                            </small>
                          </div>

                          <div>
                            <b>{severity} risk</b>
                            <small>
                              Weight:
                              {" "}
                              {indicator.weight}
                            </small>
                          </div>
                        </div>
                      );
                    }
                  )}

                  <div className="total-risk-weight">
                    <span>Total risk weight</span>
                    <strong>
                      {riskScore} / 100
                    </strong>
                  </div>
                </div>
              ) : (
                <div className="url-safe-result">
                  <CheckCircle2 size={25} />

                  <strong>
                    No common malicious URL
                    signals detected
                  </strong>
                </div>
              )}
            </article>


            <article className="url-analysis-card ai-url-card">
              <header>
                <div>
                  <BrainCircuit size={17} />
                  <h3>AI URL intelligence</h3>
                </div>

                <span className="ai-active-dot">
                  <i />
                  Active
                </span>
              </header>

              <div className="ai-intelligence-list">
                <div>
                  <span className="ai-item-icon blue">
                    <FileSearch size={16} />
                  </span>

                  <div>
                    <strong>
                      Lexical analysis
                    </strong>
                    <small>
                      Structure and content
                      evaluation
                    </small>
                  </div>

                  <b className={verdict}>
                    {verdict}
                  </b>
                </div>

                <div>
                  <span className="ai-item-icon red">
                    <Network size={16} />
                  </span>

                  <div>
                    <strong>
                      Infrastructure checks
                    </strong>
                    <small>
                      Protocol and host inspection
                    </small>
                  </div>

                  <b
                    className={
                      parsedUrl.secure
                        ? "safe"
                        : "phishing"
                    }
                  >
                    {parsedUrl.secure
                      ? "Secure"
                      : "Risk found"}
                  </b>
                </div>

                <div>
                  <span className="ai-item-icon yellow">
                    <Globe2 size={16} />
                  </span>

                  <div>
                    <strong>
                      Reputation status
                    </strong>
                    <small>
                      External reputation lookup
                    </small>
                  </div>

                  <b className="unavailable">
                    Not queried
                  </b>
                </div>

                <div>
                  <span className="ai-item-icon violet">
                    <BrainCircuit size={16} />
                  </span>

                  <div>
                    <strong>
                      Detection method
                    </strong>
                    <small>
                      Explainable hybrid engine
                    </small>
                  </div>

                  <b className="explainable">
                    XAI enabled
                  </b>
                </div>
              </div>

              <div className="url-method-box">
                <span>DETECTION METHOD</span>

                <strong>
                  {result.detectionMethod ||
                    "Hybrid explainable engine"}
                </strong>
              </div>
            </article>
          </section>


          <section className="url-explanation-card">
            <div className="url-explanation">
              <span>
                <BrainCircuit size={25} />
              </span>

              <div>
                <strong>Explanation</strong>
                <p>{explanation}</p>
              </div>
            </div>

            <div
              className={
                `url-recommendation ${verdict}`
              }
            >
              <AlertTriangle size={21} />

              <div>
                <strong>Recommendation</strong>
                <p>{recommendation}</p>
              </div>
            </div>
          </section>
        </div>
      )}
    </div>
  );
};


export default URLScanner;