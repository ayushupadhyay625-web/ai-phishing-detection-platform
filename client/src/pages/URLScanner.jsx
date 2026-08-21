import {
  AlertTriangle,
  CheckCircle2,
  ExternalLink,
  Link2,
  Search,
  ShieldAlert,
} from "lucide-react";

import { useState } from "react";
import toast from "react-hot-toast";

import api from "../api/axios";


const URLScanner = () => {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [scanning, setScanning] = useState(false);


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
            URL THREAT INTELLIGENCE
          </p>

          <h1>Malicious URL Scanner</h1>

          <p>
            Inspect suspicious links for spoofing,
            insecure protocols, redirects, and
            phishing patterns.
          </p>
        </div>
      </section>


      <section className="url-scanner-layout">
        <article className="panel">
          <div className="panel-header">
            <div>
              <span className="panel-label">
                URL INPUT
              </span>

              <h2>Link investigation</h2>
            </div>

            <Link2 size={21} />
          </div>


          <form
            className="url-scan-form"
            onSubmit={handleScan}
          >
            <label className="input-group">
              <span>Suspicious URL</span>

              <div className="url-input-wrapper">
                <Link2 size={19} />

                <input
                  type="text"
                  placeholder="https://example.com/account/verify"
                  value={url}
                  onChange={(event) =>
                    setUrl(event.target.value)
                  }
                  required
                />

                <button
                  type="submit"
                  className="primary-button"
                  disabled={scanning}
                >
                  <Search size={17} />

                  {scanning
                    ? "ANALYZING..."
                    : "ANALYZE URL"}
                </button>
              </div>
            </label>


            <div className="url-examples">
              <span>QUICK TEST:</span>

              <button
                type="button"
                onClick={() =>
                  setUrl(
                    "https://www.google.com"
                  )
                }
              >
                Safe example
              </button>

              <button
                type="button"
                onClick={() =>
                  setUrl(
                    "http://192.168.1.10/login/verify-account"
                  )
                }
              >
                Suspicious example
              </button>

              <button
                type="button"
                onClick={clearScanner}
              >
                Clear
              </button>
            </div>
          </form>
        </article>


        {!result ? (
          <article className="panel">
            <div className="empty-state url-empty">
              <Search size={42} />

              <h3>Awaiting URL analysis</h3>

              <p>
                Enter a link above to calculate its
                threat score and inspect its risk
                indicators.
              </p>
            </div>
          </article>
        ) : (
          <article className="panel url-result-panel">
            <div
              className={
                `url-verdict-banner ${result.verdict}`
              }
            >
              <div className="verdict-icon">
                {getVerdictIcon()}
              </div>

              <div>
                <span>SECURITY VERDICT</span>

                <h2>{result.verdict}</h2>
              </div>

              <div className="url-score">
                <strong>{result.riskScore}</strong>
                <span>RISK SCORE</span>
              </div>

              <div className="url-confidence">
                <strong>{result.confidence}%</strong>
                <span>CONFIDENCE</span>
              </div>
            </div>


            <div className="analyzed-url">
              <div>
                <ExternalLink size={17} />

                <span>ANALYZED URL</span>
              </div>

              <p>{result.submittedUrl}</p>
            </div>


            <div className="url-indicators">
              <div className="indicator-heading">
                <span>DETECTED RISK SIGNALS</span>

                <strong>
                  {result.detectedIndicators.length}
                </strong>
              </div>

              {result.detectedIndicators.length > 0 ? (
                <div className="url-indicator-grid">
                  {result.detectedIndicators.map(
                    (item) => (
                      <div
                        className="indicator-item"
                        key={item._id}
                      >
                        <AlertTriangle size={16} />

                        <div>
                          <strong>
                            {item.indicator}
                          </strong>

                          <span>
                            {item.category}
                          </span>
                        </div>

                        <b>+{item.weight}</b>
                      </div>
                    )
                  )}
                </div>
              ) : (
                <div className="safe-message">
                  <CheckCircle2 size={18} />

                  No common malicious URL
                  indicators were detected.
                </div>
              )}
            </div>


            <div className="method-label url-method">
              Detection method:
              <strong>
                {result.detectionMethod}
              </strong>
            </div>
          </article>
        )}
      </section>
    </>
  );
};


export default URLScanner;