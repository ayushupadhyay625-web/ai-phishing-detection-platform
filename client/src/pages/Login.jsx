import {
  useEffect,
  useState,
} from "react";

import {
  ShieldCheck,
  Eye,
  EyeOff,
  LockKeyhole,
  Mail,
  User,
} from "lucide-react";

import { useNavigate } from "react-router-dom";
import toast from "react-hot-toast";

import { useAuth } from "../context/AuthContext";


const Login = () => {
  const navigate = useNavigate();

  const {
    login,
    register,
    isAuthenticated,
  } = useAuth();

  const [isRegistering, setIsRegistering] =
    useState(false);

  const [showPassword, setShowPassword] =
    useState(false);

  const [submitting, setSubmitting] =
    useState(false);

  const [formData, setFormData] = useState({
    name: "",
    email: "",
    password: "",
  });


  useEffect(() => {
    if (isAuthenticated) {
      navigate("/dashboard", {
        replace: true,
      });
    }
  }, [isAuthenticated, navigate]);


  const handleChange = (event) => {
    const {
      name,
      value,
    } = event.target;

    setFormData((currentData) => ({
      ...currentData,
      [name]: value,
    }));
  };


  const handleSubmit = async (event) => {
    event.preventDefault();

    if (
      isRegistering &&
      formData.name.trim().length < 2
    ) {
      toast.error(
        "Please enter your full name"
      );

      return;
    }

    if (formData.password.length < 8) {
      toast.error(
        "Password must contain at least 8 characters"
      );

      return;
    }

    try {
      setSubmitting(true);

      if (isRegistering) {
        await register(
          formData.name,
          formData.email,
          formData.password
        );

        toast.success(
          "Account created successfully"
        );
      } else {
        await login(
          formData.email,
          formData.password
        );

        toast.success(
          "Secure login successful"
        );
      }

      navigate("/dashboard");
    } catch (error) {
      toast.error(
        error.response?.data?.message ||
          "Authentication failed"
      );
    } finally {
      setSubmitting(false);
    }
  };


  const changeMode = () => {
    setIsRegistering((current) => !current);

    setFormData({
      name: "",
      email: "",
      password: "",
    });

    setShowPassword(false);
  };


  return (
    <main className="auth-layout">
      <section className="auth-visual">
        <div className="auth-brand">
          <div className="brand-icon">
            <ShieldCheck size={28} />
          </div>

          <div>
            <strong>PHISHGUARD AI</strong>
            <span>EMAIL SECURITY PLATFORM</span>
          </div>
        </div>

        <div className="auth-message">
          <p className="section-label">
            INTELLIGENT THREAT DEFENSE
          </p>

          <h1>
            Stop phishing attacks
            <span> before they strike.</span>
          </h1>

          <p>
            Analyze suspicious emails and URLs
            using explainable artificial
            intelligence and real-time threat
            scoring.
          </p>

          <div className="security-features">
            <div>
              <span>01</span>
              Email-content analysis
            </div>

            <div>
              <span>02</span>
              Malicious URL detection
            </div>

            <div>
              <span>03</span>
              Explainable threat indicators
            </div>
          </div>
        </div>

        <p className="auth-copyright">
          Defensive cybersecurity platform
        </p>
      </section>


      <section className="auth-form-section">
        <div className="auth-form-card">
          <p className="section-label">
            SECURE ACCESS
          </p>

          <h2>
            {isRegistering
              ? "Create your account"
              : "Welcome back"}
          </h2>

          <p className="form-description">
            {isRegistering
              ? "Join your organization’s security workspace."
              : "Sign in to access the security operations console."}
          </p>


          <form onSubmit={handleSubmit}>
            {isRegistering && (
              <label className="input-group">
                <span>Full name</span>

                <div className="input-wrapper">
                  <User size={18} />

                  <input
                    type="text"
                    name="name"
                    placeholder="Ayush Upadhyay"
                    value={formData.name}
                    onChange={handleChange}
                    required
                  />
                </div>
              </label>
            )}


            <label className="input-group">
              <span>Email address</span>

              <div className="input-wrapper">
                <Mail size={18} />

                <input
                  type="email"
                  name="email"
                  placeholder="name@company.com"
                  value={formData.email}
                  onChange={handleChange}
                  required
                />
              </div>
            </label>


            <label className="input-group">
              <span>Password</span>

              <div className="input-wrapper">
                <LockKeyhole size={18} />

                <input
                  type={
                    showPassword
                      ? "text"
                      : "password"
                  }
                  name="password"
                  placeholder="Minimum 8 characters"
                  value={formData.password}
                  onChange={handleChange}
                  required
                  minLength={8}
                />

                <button
                  type="button"
                  className="password-toggle"
                  onClick={() =>
                    setShowPassword(
                      (current) => !current
                    )
                  }
                  aria-label="Show or hide password"
                >
                  {showPassword
                    ? <EyeOff size={18} />
                    : <Eye size={18} />}
                </button>
              </div>
            </label>


            <button
              type="submit"
              className="primary-button"
              disabled={submitting}
            >
              {submitting
                ? "PLEASE WAIT..."
                : isRegistering
                  ? "CREATE ACCOUNT"
                  : "SIGN IN SECURELY"}
            </button>
          </form>


          <button
            type="button"
            className="mode-button"
            onClick={changeMode}
          >
            {isRegistering
              ? "Already have an account? Sign in"
              : "New to PhishGuard? Create an account"}
          </button>
        </div>
      </section>
    </main>
  );
};


export default Login;