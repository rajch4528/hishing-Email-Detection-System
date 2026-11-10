# Phishing Email Detection System

A beginner-friendly, defensive Python project that checks a **saved text copy** of an email for common phishing indicators. It uses transparent rules and runs locally.

## Features
- Flags urgency, credential requests, payment pressure, generic greetings and suspicious attachment extensions.
- Extracts links and flags links that use an IP address.
- Produces a LOW / MEDIUM / HIGH heuristic risk rating.
- Makes no network requests and does not open links or attachments.
- Includes sample emails and unit tests.

## Requirements
- Python 3.9 or newer
- No third-party packages required

## Run it
```bash
python phishing_detector.py samples/suspicious_email.txt
```
Try the safer sample too:
```bash
python phishing_detector.py samples/normal_email.txt
```

## Run tests
```bash
python -m unittest discover -s tests -v
```

## How the score works
Each matched rule adds points. The score is capped at 10:
- LOW: 0–2
- MEDIUM: 3–5
- HIGH: 6–10

This is a learning demo, not a production email security gateway. Heuristics can produce false positives and false negatives. Never treat LOW as proof that a message is safe.

## Project structure
```text
phishing-email-detector/
├── phishing_detector.py
├── README.md
├── requirements.txt
├── .gitignore
├── samples/
│   ├── normal_email.txt
│   └── suspicious_email.txt
└── tests/
    └── test_detector.py
```

## Responsible use
Use only emails you own or are authorized to analyze. For privacy, use synthetic examples or remove personal information before testing. Do not click links, download attachments, or enter credentials while investigating a suspicious message.

## Ideas for future improvements
- Add a CSV report export.
- Add sender-domain and display-name mismatch checks using safely supplied headers.
- Add a simple web interface.
- Compare results against a labeled educational dataset and measure precision/recall.
