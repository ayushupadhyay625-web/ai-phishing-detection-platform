

# AI-Powered Phishing Detection and Email Security Platform

A full-stack cybersecurity platform that detects phishing emails, analyzes malicious URLs, generates explainable risk scores, stores security scan history, and collects analyst feedback for future model improvement.

## Features

- Secure user registration and login using JWT
- Password encryption using bcrypt
- Role-based access for Admin, Security Analyst, and User
- Phishing email-content analysis
- Malicious URL detection
- Hybrid rule-based and machine-learning risk scoring
- TF-IDF and Logistic Regression email classification
- Explainable threat indicators
- MongoDB scan history
- Security analytics dashboard
- CSV security reports
- Analyst feedback and corrected verdict collection
- Responsive React interface

## Technology Stack

### Frontend

- React.js
- Vite
- React Router
- Axios
- Recharts
- React Hot Toast
- Lucide React

### Backend

- Node.js
- Express.js
- MongoDB
- Mongoose
- JWT
- bcrypt
- Helmet
- Morgan

### Machine Learning

- Python
- Flask
- scikit-learn
- TF-IDF Vectorization
- Logistic Regression
- Joblib
- Pandas
- NumPy

## System Architecture

```text
React Frontend
      |
      v
Node.js and Express API
      |
      +---- MongoDB
      |
      v
Python Flask Detection Service
      |
      +---- Rule-Based Detection Engine
      |
      +---- Trained Machine-Learning Model

## Live Deployment

- Web Application: https://phishguard-ai-vpn4.onrender.com
- Backend API: https://phishguard-api-e7bh.onrender.com
- ML Service Health: https://phishguard-ml-service.onrender.com/api/health

> The services use Render’s free tier, so the first request after inactivity may take up to two minutes.      