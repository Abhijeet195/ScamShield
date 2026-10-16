import { useEffect, useState } from "react";
import "./App.css";

const API_BASE_URL = "http://127.0.0.1:5000";

// Reusable performance metric card
function MetricCard({ title, value, description }) {
  return (
    <article className="metric-card">
      <span className="metric-title">{title}</span>
      <strong className="metric-value">{value}</strong>
      <p>{description}</p>
    </article>
  );
}

function App() {
  const [message, setMessage] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const [metrics, setMetrics] = useState(null);
  const [metricsError, setMetricsError] = useState("");
  const [metricsLoading, setMetricsLoading] = useState(true);

  // ================================================
  // 1. LOAD MODEL PERFORMANCE METRICS
  // ================================================

  useEffect(() => {
    const controller = new AbortController();

    async function loadMetrics() {
      try {
        const response = await fetch(
          `${API_BASE_URL}/api/metrics`,
          {
            signal: controller.signal,
          }
        );

        const data = await response.json();

        if (!response.ok) {
          throw new Error(
            data.error || "Unable to load model metrics."
          );
        }

        setMetrics(data);
        setMetricsError("");
      } catch (err) {
        if (err.name !== "AbortError") {
          setMetricsError(
            "Unable to load metrics. Check whether Flask is running."
          );
        }
      } finally {
        if (!controller.signal.aborted) {
          setMetricsLoading(false);
        }
      }
    }

    loadMetrics();

    return () => controller.abort();
  }, []);

  // ================================================
  // 2. ANALYZE A MESSAGE
  // ================================================

  async function analyzeMessage(event) {
    event.preventDefault();

    setError("");
    setResult(null);

    if (!message.trim()) {
      setError("Please enter a message to analyze.");
      return;
    }

    setLoading(true);

    try {
      const response = await fetch(
        `${API_BASE_URL}/api/predict`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            message: message.trim(),
          }),
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.error || "Unable to analyze the message."
        );
      }

      setResult(data);
    } catch (err) {
      console.error("Prediction error:", err);

      setError(
        err.message ||
          "Cannot connect to Flask. Check the backend server."
      );
    } finally {
      setLoading(false);
    }
  }

  // ================================================
  // 3. CLEAR THE MESSAGE
  // ================================================

  function clearMessage() {
    setMessage("");
    setResult(null);
    setError("");
  }

  const isSpam = result?.prediction === "spam";

  // ================================================
  // 4. RENDER THE APPLICATION
  // ================================================

  return (
    <div className="app">

      {/* Navigation bar */}

      <nav className="navbar">
        <a className="brand" href="#home">
          <span className="brand-icon">S</span>
          <span>ScamShield</span>
        </a>

        <div className="nav-status">
          <span className="status-dot"></span>
          AI Message Protection
        </div>
      </nav>

      <main className="container">

        {/* Hero section */}

        <section className="hero" id="home">
          <div className="eyebrow">
            INTELLIGENT MESSAGE SECURITY
          </div>

          <h1>
            Think before
            <br />
            <span>you click.</span>
          </h1>

          <p className="hero-description">
            Analyze suspicious messages using machine learning.
            Identify potential spam and receive a warning before
            interacting with questionable content.
          </p>
        </section>

        {/* ==========================================
            AI PERFORMANCE DASHBOARD
        =========================================== */}

        <section className="dashboard">
          <div className="dashboard-heading">
            <div>
              <div className="eyebrow">
                MODEL PERFORMANCE
              </div>

              <h2>AI Performance Dashboard</h2>

              <p>
                Performance metrics from the model's held-out
                test dataset.
              </p>
            </div>

            {metrics && (
              <span className="model-badge">
                {metrics.selected_model}
              </span>
            )}
          </div>

          {metricsLoading && (
            <div className="loading-box">
              Loading model performance metrics...
            </div>
          )}

          {!metricsLoading && metricsError && (
            <div className="error-box" role="alert">
              {metricsError}
            </div>
          )}

          {metrics && (
            <>
              {/* Performance cards */}

              <div className="metric-grid">
                <MetricCard
                  title="Test Accuracy"
                  value={`${(
                    metrics.accuracy * 100
                  ).toFixed(2)}%`}
                  description="Overall correct predictions"
                />

                <MetricCard
                  title="Spam Precision"
                  value={`${(
                    metrics.spam_precision * 100
                  ).toFixed(2)}%`}
                  description="Correctness of spam predictions"
                />

                <MetricCard
                  title="Spam Recall"
                  value={`${(
                    metrics.spam_recall * 100
                  ).toFixed(2)}%`}
                  description="Actual spam messages detected"
                />

                <MetricCard
                  title="Spam F1-score"
                  value={`${(
                    metrics.spam_f1 * 100
                  ).toFixed(2)}%`}
                  description="Balance of precision and recall"
                />
              </div>

              {/* Confusion matrix */}

              <div className="matrix-card">
                <div className="matrix-heading">
                  <h3>Confusion Matrix</h3>

                  <p>
                    Model predictions for{" "}
                    {metrics.test_samples} test messages.
                  </p>
                </div>

                <div className="table-wrapper">
                  <table className="confusion-table">
                    <thead>
                      <tr>
                        <th>Actual / Predicted</th>

                        {metrics.confusion_matrix.labels.map(
                          (label) => (
                            <th key={label} scope="col">
                              {label}
                            </th>
                          )
                        )}
                      </tr>
                    </thead>

                    <tbody>
                      {metrics.confusion_matrix.labels.map(
                        (label, rowIndex) => (
                          <tr key={label}>
                            <th scope="row">{label}</th>

                            {metrics.confusion_matrix.values[
                              rowIndex
                            ].map((value, columnIndex) => (
                              <td
                                key={`${rowIndex}-${columnIndex}`}
                              >
                                {value}
                              </td>
                            ))}
                          </tr>
                        )
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

              <p className="dashboard-note">
                These metrics describe performance on the held-out
                test set. Because the dataset labels spam and
                non-spam messages rather than independently
                verified scams, real-world scam-detection
                performance may differ.
              </p>
            </>
          )}
        </section>

        {/* ==========================================
            MESSAGE ANALYZER
        =========================================== */}

        <section className="analyzer">
          <div className="section-header">
            <div>
              <h2>Message Analyzer</h2>
              <p>
                Paste a message below to check its classification.
              </p>
            </div>

            <span className="ai-badge">AI POWERED</span>
          </div>

          <form onSubmit={analyzeMessage}>
            <label htmlFor="message">
              MESSAGE CONTENT
            </label>

            <textarea
              id="message"
              rows={6}
              maxLength={5000}
              value={message}
              onChange={(event) => {
                setMessage(event.target.value);
                setResult(null);
                setError("");
              }}
              placeholder="Paste an SMS, promotional message, or suspicious text here..."
            />

            <div className="input-footer">
              <span>
                {message.length}/5000 characters
              </span>

              <button
                type="button"
                className="clear-button"
                onClick={clearMessage}
              >
                Clear
              </button>
            </div>

            <button
              type="submit"
              className="analyze-button"
              disabled={loading}
            >
              {loading
                ? "Analyzing Message..."
                : "Analyze Message →"}
            </button>
          </form>

          {error && (
            <div className="error-box" role="alert">
              {error}
            </div>
          )}

          {/* Prediction result */}

          {result && (
            <div
              className={`result-card ${
                isSpam ? "result-spam" : "result-ham"
              }`}
              aria-live="polite"
            >
              <div className="result-header">
                <div>
                  <span className="result-caption">
                    AI MODEL PREDICTION
                  </span>

                  <h3>{result.label}</h3>
                </div>

                <div className="result-icon">
                  {isSpam ? "!" : "✓"}
                </div>
              </div>

              <p className="warning-text">
                {result.warning}
              </p>

              <div className="probability">
                <div className="probability-header">
                  <span>
                    Estimated spam probability
                  </span>

                  <strong>
                    {result.spam_probability}%
                  </strong>
                </div>

                <div className="progress-track">
                  <div
                    className={`progress-fill ${
                      isSpam ? "spam-fill" : "ham-fill"
                    }`}
                    style={{
                      width: `${result.spam_probability}%`,
                    }}
                  ></div>
                </div>
              </div>
            </div>
          )}

          <p className="disclaimer">
            ScamShield provides automated predictions, not
            guarantees. A message that is not flagged as spam
            may still be fraudulent. Independently verify
            suspicious links and requests for sensitive information.
          </p>
        </section>

        {/* Project features */}

        <section className="features">
          <article className="feature-card">
            <span className="feature-number">01</span>
            <h3>Text Analysis</h3>
            <p>
              TF-IDF converts message text into numerical features
              for machine learning.
            </p>
          </article>

          <article className="feature-card">
            <span className="feature-number">02</span>
            <h3>AI Classification</h3>
            <p>
              A trained Logistic Regression or Naive Bayes model
              classifies messages as spam or not spam.
            </p>
          </article>

          <article className="feature-card">
            <span className="feature-number">03</span>
            <h3>Security Awareness</h3>
            <p>
              Prediction results help users exercise caution
              around potentially suspicious messages.
            </p>
          </article>
        </section>

      </main>

      {/* Footer */}

      <footer className="footer">
        <span>ScamShield · Mini-Hackathon PS 10</span>
        <span>AI-Powered Message Classification</span>
      </footer>
    </div>
  );
}

export default App;