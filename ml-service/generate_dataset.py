import csv
import random
from pathlib import Path


random.seed(42)

BASE_DIRECTORY = Path(__file__).resolve().parent
DATA_DIRECTORY = BASE_DIRECTORY / "data"
OUTPUT_FILE = DATA_DIRECTORY / "phishing_emails_1000.csv"

RECORDS_PER_CLASS = 500


PHISHING_SENDERS = [
    "security@unknown-bank-alert.com",
    "support@account-verification.net",
    "admin@secure-login-update.com",
    "billing@payment-review-alert.com",
    "helpdesk@password-confirmation.net",
    "service@urgent-account-check.com",
    "rewards@claim-prize-now.net",
    "delivery@parcel-update-alert.com",
    "notice@tax-refund-review.com",
    "security@cloud-storage-warning.net",
]


PHISHING_SUBJECTS = [
    "URGENT: Verify Your Account Immediately",
    "Your Account Has Been Suspended",
    "Security Alert: Password Confirmation Required",
    "Immediate Action Required",
    "Unusual Login Attempt Detected",
    "Confirm Your Banking Information",
    "Your Payment Was Declined",
    "Claim Your Reward Before It Expires",
    "Package Delivery Failed",
    "Your Mailbox Storage Is Full",
    "Tax Refund Confirmation Required",
    "Final Warning: Account Will Be Closed",
]


PHISHING_OPENINGS = [
    "We detected suspicious activity on your account.",
    "Your account has temporarily been suspended.",
    "An unauthorized login attempt was detected.",
    "Your recent payment could not be processed.",
    "Your identity information requires immediate verification.",
    "Your package cannot be delivered until your address is confirmed.",
    "Your mailbox will be disabled because it has exceeded its storage limit.",
    "You have been selected to receive a limited reward.",
]


PHISHING_ACTIONS = [
    "Verify your password and OTP immediately",
    "Confirm your account information now",
    "Update your payment information",
    "Sign in to prevent permanent account closure",
    "Validate your identity within 24 hours",
    "Confirm your delivery address",
    "Unlock your account using the secure link",
    "Submit your banking information to receive the refund",
]


PHISHING_LINKS = [
    "http://192.168.1.10/login/verify-account",
    "http://account-security-check.example/login",
    "http://secure-update.example/confirm-password",
    "http://payment-review.example/billing",
    "http://delivery-confirmation.example/update",
    "http://reward-claim.example/winner",
    "http://mailbox-validation.example/signin",
    "http://refund-processing.example/verify",
]


PHISHING_CLOSINGS = [
    "Failure to respond may result in permanent suspension.",
    "This request will expire within 24 hours.",
    "Act immediately to avoid interruption of service.",
    "Ignoring this message may result in account closure.",
    "This is your final security warning.",
]


SAFE_SENDERS = [
    "newsletter@company.example",
    "hr@company.example",
    "support@trusted-service.example",
    "team@project.example",
    "billing@subscription.example",
    "events@community.example",
    "updates@software.example",
    "manager@company.example",
    "notifications@calendar.example",
    "orders@shop.example",
]


SAFE_SUBJECTS = [
    "Weekly Project Update",
    "Meeting Agenda for Tomorrow",
    "Your Monthly Account Statement",
    "Welcome to Our Newsletter",
    "Team Performance Summary",
    "Your Order Has Been Shipped",
    "Software Update Release Notes",
    "Reminder: Upcoming Team Meeting",
    "Monthly Subscription Receipt",
    "Community Event Invitation",
    "Employee Training Schedule",
    "Thank You for Your Feedback",
]


SAFE_OPENINGS = [
    "Here is the latest update from our team.",
    "This message contains the agenda for our upcoming meeting.",
    "Your monthly statement is now available for review.",
    "Thank you for subscribing to our newsletter.",
    "The project team completed this week's planned activities.",
    "Your order has been processed and shipped.",
    "A new software update is available with performance improvements.",
    "This is a reminder about the scheduled team meeting.",
]


SAFE_DETAILS = [
    "No action is required at this time.",
    "You can review the information from your normal account dashboard.",
    "Please contact your manager if you have any questions.",
    "The attached summary contains the latest approved information.",
    "We appreciate your continued participation.",
    "You may ignore this message if you have already completed the task.",
    "The meeting will take place during normal business hours.",
    "Your existing password and account settings remain unchanged.",
]


SAFE_CLOSINGS = [
    "Regards, The Support Team",
    "Thank you, Human Resources",
    "Best regards, Project Management",
    "Sincerely, Customer Support",
    "Thanks, The Community Team",
    "Regards, Account Services",
]


def generate_phishing_email(index):
    sender = random.choice(PHISHING_SENDERS)
    subject = random.choice(PHISHING_SUBJECTS)
    opening = random.choice(PHISHING_OPENINGS)
    action = random.choice(PHISHING_ACTIONS)
    link = random.choice(PHISHING_LINKS)
    closing = random.choice(PHISHING_CLOSINGS)

    body = (
        f"Dear Customer, {opening} "
        f"{action}: {link}. "
        f"{closing} Reference ID: PH-{index:04d}."
    )

    return {
        "id": f"phishing-{index:04d}",
        "sender": sender,
        "subject": subject,
        "body": body,
        "text": f"{subject} {body}",
        "label": "phishing",
        "label_numeric": 1,
    }


def generate_safe_email(index):
    sender = random.choice(SAFE_SENDERS)
    subject = random.choice(SAFE_SUBJECTS)
    opening = random.choice(SAFE_OPENINGS)
    details = random.choice(SAFE_DETAILS)
    closing = random.choice(SAFE_CLOSINGS)

    body = (
        f"Hello, {opening} "
        f"{details} {closing}. "
        f"Message reference: SAFE-{index:04d}."
    )

    return {
        "id": f"safe-{index:04d}",
        "sender": sender,
        "subject": subject,
        "body": body,
        "text": f"{subject} {body}",
        "label": "safe",
        "label_numeric": 0,
    }


def generate_dataset():
    records = []

    for index in range(1, RECORDS_PER_CLASS + 1):
        records.append(
            generate_phishing_email(index)
        )

        records.append(
            generate_safe_email(index)
        )

    random.shuffle(records)

    DATA_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    fieldnames = [
        "id",
        "sender",
        "subject",
        "body",
        "text",
        "label",
        "label_numeric",
    ]

    with OUTPUT_FILE.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as csv_file:
        writer = csv.DictWriter(
            csv_file,
            fieldnames=fieldnames,
        )

        writer.writeheader()
        writer.writerows(records)

    phishing_count = sum(
        record["label"] == "phishing"
        for record in records
    )

    safe_count = sum(
        record["label"] == "safe"
        for record in records
    )

    print("Dataset generated successfully")
    print(f"File: {OUTPUT_FILE}")
    print(f"Total records: {len(records)}")
    print(f"Phishing records: {phishing_count}")
    print(f"Safe records: {safe_count}")


if __name__ == "__main__":
    generate_dataset()