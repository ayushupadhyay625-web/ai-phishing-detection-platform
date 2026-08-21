import csv
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
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

from sklearn.model_selection import (
    train_test_split,
)

from sklearn.pipeline import Pipeline


BASE_DIRECTORY = Path(__file__).resolve().parent

DATASET_PATH = (
    BASE_DIRECTORY
    / "data"
    / "phishing_emails_1000.csv"
)

MODEL_DIRECTORY = (
    BASE_DIRECTORY / "models"
)

MODEL_PATH = (
    MODEL_DIRECTORY
    / "phishing_email_model.joblib"
)

RANDOM_STATE = 42


def load_training_dataset():
    if not DATASET_PATH.exists():
        raise FileNotFoundError(
            "Training dataset was not found at: "
            f"{DATASET_PATH}\n"
            "Run generate_dataset.py first."
        )

    messages = []
    labels = []

    with DATASET_PATH.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as csv_file:
        reader = csv.DictReader(csv_file)

        required_columns = {
            "subject",
            "body",
            "label",
        }

        available_columns = set(
            reader.fieldnames or []
        )

        missing_columns = (
            required_columns
            - available_columns
        )

        if missing_columns:
            raise ValueError(
                "Dataset is missing these columns: "
                + ", ".join(
                    sorted(missing_columns)
                )
            )

        for row in reader:
            subject = (
                row.get("subject", "")
                .strip()
            )

            body = (
                row.get("body", "")
                .strip()
            )

            sender = (
                row.get("sender", "")
                .strip()
            )

            label = (
                row.get("label", "")
                .strip()
                .lower()
            )

            if label not in {
                "safe",
                "phishing",
            }:
                continue

            message = (
                f"Sender: {sender}\n"
                f"Subject: {subject}\n"
                f"Body: {body}"
            )

            if not message.strip():
                continue

            messages.append(message)
            labels.append(label)

    if len(messages) < 10:
        raise ValueError(
            "The training dataset does not "
            "contain enough valid records."
        )

    safe_count = labels.count("safe")

    phishing_count = labels.count(
        "phishing"
    )

    if (
        safe_count == 0
        or phishing_count == 0
    ):
        raise ValueError(
            "The dataset must contain both "
            "safe and phishing records."
        )

    print("=" * 60)
    print("PHISHGUARD AI MODEL TRAINING")
    print("=" * 60)

    print(
        f"Dataset file: {DATASET_PATH}"
    )

    print(
        f"Total valid records: {len(messages)}"
    )

    print(
        f"Safe records: {safe_count}"
    )

    print(
        f"Phishing records: {phishing_count}"
    )

    return messages, labels


def create_model_pipeline():
    return Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    lowercase=True,
                    strip_accents="unicode",
                    stop_words="english",
                    ngram_range=(1, 2),
                    min_df=2,
                    max_df=0.98,
                    max_features=12000,
                    sublinear_tf=True,
                ),
            ),
            (
                "classifier",
                LogisticRegression(
                    max_iter=2000,
                    class_weight="balanced",
                    solver="liblinear",
                    random_state=RANDOM_STATE,
                ),
            ),
        ]
    )


def evaluate_model(
    model_pipeline,
    testing_messages,
    testing_labels,
):
    predictions = model_pipeline.predict(
        testing_messages
    )

    accuracy = accuracy_score(
        testing_labels,
        predictions,
    )

    precision = precision_score(
        testing_labels,
        predictions,
        pos_label="phishing",
        zero_division=0,
    )

    recall = recall_score(
        testing_labels,
        predictions,
        pos_label="phishing",
        zero_division=0,
    )

    f1 = f1_score(
        testing_labels,
        predictions,
        pos_label="phishing",
        zero_division=0,
    )

    matrix = confusion_matrix(
        testing_labels,
        predictions,
        labels=[
            "safe",
            "phishing",
        ],
    )

    print("\n" + "=" * 60)
    print("MODEL EVALUATION")
    print("=" * 60)

    print(
        f"Accuracy:  {accuracy * 100:.2f}%"
    )

    print(
        f"Precision: {precision * 100:.2f}%"
    )

    print(
        f"Recall:    {recall * 100:.2f}%"
    )

    print(
        f"F1 score:  {f1 * 100:.2f}%"
    )

    print("\nClassification report:")

    print(
        classification_report(
            testing_labels,
            predictions,
            labels=[
                "safe",
                "phishing",
            ],
            zero_division=0,
        )
    )

    print("Confusion matrix:")

    print(
        "Rows: actual labels"
    )

    print(
        "Columns: predicted labels"
    )

    print(
        "Label order: safe, phishing"
    )

    print(matrix)

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def test_sample_predictions(
    model_pipeline,
):
    sample_messages = [
        (
            "Sender: manager@company.example\n"
            "Subject: Weekly project update\n"
            "Body: The project meeting will "
            "take place tomorrow at 10 AM."
        ),
        (
            "Sender: security@unknown-alert.example\n"
            "Subject: URGENT ACCOUNT SUSPENDED\n"
            "Body: Verify your password and OTP "
            "immediately using the link below."
        ),
    ]

    print("\n" + "=" * 60)
    print("SAMPLE PREDICTIONS")
    print("=" * 60)

    for message in sample_messages:
        prediction = (
            model_pipeline.predict(
                [message]
            )[0]
        )

        probabilities = (
            model_pipeline.predict_proba(
                [message]
            )[0]
        )

        class_names = (
            model_pipeline.named_steps[
                "classifier"
            ].classes_
        )

        probability_map = dict(
            zip(
                class_names,
                probabilities,
            )
        )

        phishing_probability = (
            probability_map.get(
                "phishing",
                0,
            )
        )

        subject_line = (
            message.split("\n")[1]
            .replace(
                "Subject: ",
                "",
            )
        )

        print(
            f"\nSubject: {subject_line}"
        )

        print(
            f"Prediction: {prediction}"
        )

        print(
            "Phishing probability: "
            f"{phishing_probability * 100:.2f}%"
        )


def save_model(model_pipeline):
    MODEL_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    joblib.dump(
        model_pipeline,
        MODEL_PATH,
    )

    print("\n" + "=" * 60)
    print("MODEL SAVED")
    print("=" * 60)

    print(
        f"Model saved to: {MODEL_PATH}"
    )


def train_model():
    messages, labels = (
        load_training_dataset()
    )

    (
        training_messages,
        testing_messages,
        training_labels,
        testing_labels,
    ) = train_test_split(
        messages,
        labels,
        test_size=0.20,
        random_state=RANDOM_STATE,
        stratify=labels,
    )

    print(
        "\nTraining records: "
        f"{len(training_messages)}"
    )

    print(
        "Testing records: "
        f"{len(testing_messages)}"
    )

    model_pipeline = (
        create_model_pipeline()
    )

    print("\nTraining model...")

    model_pipeline.fit(
        training_messages,
        training_labels,
    )

    evaluate_model(
        model_pipeline,
        testing_messages,
        testing_labels,
    )

    test_sample_predictions(
        model_pipeline
    )

    save_model(model_pipeline)

    print(
        "\nTraining completed successfully."
    )


if __name__ == "__main__":
    train_model()