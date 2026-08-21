from pathlib import Path

import joblib

from sklearn.feature_extraction.text import (
    TfidfVectorizer,
)

from sklearn.linear_model import (
    LogisticRegression,
)

from sklearn.metrics import (
    accuracy_score,
    classification_report,
)

from sklearn.model_selection import (
    train_test_split,
)

from sklearn.pipeline import Pipeline


BASE_DIRECTORY = Path(__file__).resolve().parent

MODEL_DIRECTORY = BASE_DIRECTORY / "models"

MODEL_PATH = (
    MODEL_DIRECTORY /
    "phishing_email_model.joblib"
)


SAFE_EMAILS = [
    "Your meeting is scheduled for Monday at 10 AM.",
    "Please find the monthly sales report attached.",
    "Thank you for completing the project documentation.",
    "Your leave request has been approved.",
    "The development team will deploy the update tonight.",
    "Please review the attached invoice for our recent order.",
    "Your interview has been scheduled for tomorrow.",
    "The office will remain closed during the public holiday.",
    "Here are the minutes from our weekly team meeting.",
    "Your package has been dispatched and will arrive tomorrow.",
    "Please submit your attendance report before Friday.",
    "The customer support team resolved your ticket.",
    "Welcome to the organization. Your employee account is ready.",
    "The quarterly performance review meeting is next week.",
    "Your password was changed successfully as requested.",
    "Your training session begins at 2 PM today.",
    "Please review the latest project requirements.",
    "The payment for invoice 2045 has been received.",
    "Your reservation is confirmed for this weekend.",
    "The updated company policy is available on the employee portal.",
    "Please join the video conference using the official company calendar.",
    "Your account statement is available through the official banking application.",
    "The security team completed the scheduled maintenance.",
    "Thank you for attending yesterday's workshop.",
    "Your request has been received and is being processed.",
    "The finance department has approved your reimbursement.",
    "The attached document contains the final project proposal.",
    "Please remember to update your weekly task status.",
    "Your subscription renewal was completed successfully.",
    "This is a reminder for your appointment tomorrow morning.",
]


PHISHING_EMAILS = [
    "URGENT! Your account is suspended. Verify your password immediately.",
    "Click here now to confirm your bank account and avoid permanent closure.",
    "You won a cash prize. Send your OTP to claim it immediately.",
    "Your mailbox storage is full. Login now to prevent email deletion.",
    "Unusual activity detected. Verify your account through this link.",
    "Your payment failed. Update your card number and CVV immediately.",
    "Final warning! Your account will be terminated unless you confirm your password.",
    "Congratulations winner. Click the link to receive your free reward.",
    "Security alert. Enter your OTP and PIN to restore account access.",
    "Your tax refund is waiting. Submit your bank information now.",
    "We detected suspicious login activity. Verify your credentials urgently.",
    "Your salary payment is blocked. Confirm your banking password.",
    "Click this shortened link to reactivate your suspended account.",
    "Your social media profile has been reported. Login immediately.",
    "Bank security notice. Confirm account details to avoid deactivation.",
    "You have received an unexpected payment. Verify your identity now.",
    "Your delivery cannot be completed. Pay the small redelivery fee.",
    "Important invoice attached. Enable macros to view the document.",
    "Your company email will expire today. Enter your password to continue.",
    "Emergency request from the CEO. Purchase gift cards immediately.",
    "Your cloud files will be deleted. Login through the secure link now.",
    "Account verification required. Provide password OTP and card PIN.",
    "You are selected for a reward. Click here and submit payment details.",
    "Your bank account has been compromised. Confirm credentials urgently.",
    "Limited time refund available. Enter your debit card information.",
    "Your employee payroll account is locked. Verify your password now.",
    "Download the attachment and enable editing to view the confidential file.",
    "Your streaming subscription was suspended. Update payment information.",
    "Immediate action required. Confirm your identity using the link below.",
    "Your email account has exceeded its limit. Login to keep your messages.",
]


def create_training_dataset():
    messages = SAFE_EMAILS + PHISHING_EMAILS

    labels = (
        ["safe"] * len(SAFE_EMAILS)
        + ["phishing"] * len(PHISHING_EMAILS)
    )

    return messages, labels


def train_model():
    messages, labels = create_training_dataset()

    (
        training_messages,
        testing_messages,
        training_labels,
        testing_labels,
    ) = train_test_split(
        messages,
        labels,
        test_size=0.25,
        random_state=42,
        stratify=labels,
    )


    model_pipeline = Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    lowercase=True,
                    stop_words="english",
                    ngram_range=(1, 2),
                    max_features=5000,
                ),
            ),

            (
                "classifier",
                LogisticRegression(
                    max_iter=1000,
                    class_weight="balanced",
                    random_state=42,
                ),
            ),
        ]
    )


    model_pipeline.fit(
        training_messages,
        training_labels,
    )


    predictions = model_pipeline.predict(
        testing_messages
    )


    accuracy = accuracy_score(
        testing_labels,
        predictions,
    )


    print(
        f"Model accuracy: {accuracy * 100:.2f}%"
    )

    print(
        classification_report(
            testing_labels,
            predictions,
        )
    )


    MODEL_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    joblib.dump(
        model_pipeline,
        MODEL_PATH,
    )


    print(
        f"Model saved to: {MODEL_PATH}"
    )


if __name__ == "__main__":
    train_model()