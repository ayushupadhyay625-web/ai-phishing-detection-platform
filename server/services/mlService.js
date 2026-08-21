const getMLServiceURL = () => {
  return (
    process.env.ML_SERVICE_URL ||
    "http://127.0.0.1:5001"
  );
};

const sendPredictionRequest = async (
  endpoint,
  requestData
) => {
  try {
    const response = await fetch(
      `${getMLServiceURL()}${endpoint}`,
      {
        method: "POST",

        headers: {
          "Content-Type": "application/json",
        },

        body: JSON.stringify(requestData),

        signal: AbortSignal.timeout(120000),
      }
    );

    const responseData = await response.json();

    if (!response.ok) {
      throw new Error(
        responseData.message ||
          "The detection service rejected the request"
      );
    }

    return responseData;
  } catch (error) {
    if (error.name === "TimeoutError") {
      throw new Error(
        "The detection service took too long to respond"
      );
    }

    if (
      error.cause?.code === "ECONNREFUSED" ||
      error.message.includes("fetch failed")
    ) {
      throw new Error(
        "Python detection service is unavailable"
      );
    }

    throw error;
  }
};

export const analyzeEmailWithML = async (emailData) => {
  return sendPredictionRequest(
    "/api/predict/email",
    emailData
  );
};

export const analyzeURLWithML = async (url) => {
  return sendPredictionRequest(
    "/api/predict/url",
    {
      url,
    }
  );
};

export const checkMLServiceHealth = async () => {
  try {
    const response = await fetch(
      `${getMLServiceURL()}/api/health`,
      {
        signal: AbortSignal.timeout(5000),
      }
    );

    if (!response.ok) {
      return {
        available: false,
      };
    }

    const data = await response.json();

    return {
      available: true,
      ...data,
    };
  } catch (error) {
    return {
      available: false,
      message: error.message,
    };
  }
};