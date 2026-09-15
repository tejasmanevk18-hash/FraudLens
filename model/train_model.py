


"""
model/train_model.py — FraudLens SMS scam classifier training script.

Run this ONCE (or whenever you want to retrain) — the Flask app does not
train on every startup, it just loads the saved .pkl files.

    python model/train_model.py

Pipeline
--------
    raw SMS text
        -> lightweight text cleaning
        -> TF-IDF vectorization
        -> Logistic Regression vs Multinomial Naive Bayes
        -> the better-performing model (by F1-score) is saved

Outputs
-------
    model/sms_model.pkl      (trained classifier)
    model/vectorizer.pkl     (fitted TF-IDF vectorizer)

Dataset note (IMPORTANT — read this)
-------------------------------------
This project is normally trained on the public "SMS Spam Collection
Dataset" (UCI / Kaggle). This build environment has no internet access,
so this script will AUTO-GENERATE a synthetic-but-realistic dataset at
dataset/sms_spam_dataset.csv the first time it runs, using a wide set of
scam/ham sentence templates with randomized fillers.

To use the REAL dataset instead:
  1. Download the "SMS Spam Collection Dataset" (columns: label, message
     where label is "spam" or "ham").
  2. Save it as dataset/sms_spam_dataset.csv (same column names).
  3. Delete the auto-generated file first if one already exists, or just
     overwrite it.
  4. Re-run this script.

No other code needs to change — app.py only ever loads the saved .pkl
files, so swapping the dataset and retraining is a drop-in upgrade.
"""

import random
import re
from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB

BASE_DIR = Path(__file__).resolve().parent.parent
DATASET_PATH = BASE_DIR / "dataset" / "sms_spam_dataset.csv"
MODEL_PATH = Path(__file__).resolve().parent / "sms_model.pkl"
VECTORIZER_PATH = Path(__file__).resolve().parent / "vectorizer.pkl"

random.seed(42)


# ---------------------------------------------------------------------------
# 1. Synthetic dataset generation (only runs if no dataset file exists yet)
# ---------------------------------------------------------------------------
def generate_synthetic_dataset(n_per_class: int = 350) -> pd.DataFrame:
    banks = ["SBI", "HDFC Bank", "ICICI Bank", "Axis Bank", "your bank", "PNB", "Kotak Bank"]
    amounts = ["Rs. 4,999", "Rs. 25,000", "Rs. 999", "Rs. 1,20,000", "Rs. 499", "$500", "Rs. 15,750"]
    links = ["http://bit.ly/verify-now", "http://secure-kyc-update.info/login",
             "http://tinyurl.com/claim-reward", "http://account-verify.top/otp",
             "http://payment-refund.xyz/claim", "http://t.co/x9Ks2"]
    names = ["Rahul", "Priya", "Amit", "Sneha", "Arjun", "Neha", "Vikram", "Anjali"]
    companies = ["Amazon", "Flipkart", "Netflix", "PayTM", "Google Pay", "your telecom provider"]

    spam_templates = [
        "URGENT: Your {bank} account has been suspended. Verify your KYC immediately at {link} or it will be permanently blocked.",
        "Congratulations! You have won {amount} in the lucky draw. Claim now at {link} before it expires today.",
        "Dear customer, your ATM card will be blocked today. Update your details now: {link}",
        "Your {company} account shows unusual activity. Confirm your password at {link} to avoid suspension.",
        "Final notice: pay {amount} immediately or legal action will be taken. Pay now at {link}",
        "You have received a refund of {amount}. Click {link} and enter your OTP to receive the amount.",
        "Your parcel is on hold due to unpaid customs fee of {amount}. Pay here: {link}",
        "Alert! Someone tried to login to your account. Verify identity now at {link} within 24 hours.",
        "Free recharge of {amount} is waiting for you! Click {link} now, offer ends soon.",
        "Your {bank} debit card is expiring today. Renew instantly by sharing OTP sent to your phone.",
        "Job offer: Earn {amount} per day working from home. Register now at {link}, limited seats!",
        "Your electricity bill of {amount} is overdue and will be disconnected tonight. Pay immediately: {link}",
        "CONGRATULATIONS {name}! Your number has won a lottery of {amount}. Reply with your bank details to claim.",
        "Your {company} subscription payment failed. Update payment info urgently at {link} to avoid account closure.",
        "Limited time offer! Get {amount} cashback instantly, just verify your UPI PIN at {link}",
        "We could not deliver your package. Reschedule and pay {amount} fee at {link} within 12 hours.",
        "Your income tax refund of {amount} is approved. Submit your bank details at {link} to receive it.",
        "Security alert: unusual sign-in detected. Confirm it's you and enter OTP at {link} immediately.",
    ]

    ham_templates = [
        "Hey {name}, are we still meeting for lunch tomorrow at 1pm?",
        "Don't forget to bring the documents for the meeting on Monday.",
        "Happy birthday {name}! Hope you have a wonderful day.",
        "Can you send me the notes from today's class?",
        "Your OTP for login is 483920. Do not share this with anyone.",
        "Reminder: your appointment with Dr. Sharma is scheduled for 4:30 PM today.",
        "Thanks for the help yesterday, really appreciate it!",
        "Mom, I'll be home by 8, please don't wait for dinner.",
        "Your order from {company} has been shipped and will arrive in 2 days.",
        "Let's catch up this weekend, it's been a while!",
        "The project deadline has been moved to next Friday.",
        "Can you pick up milk on your way home?",
        "Meeting rescheduled to 3 PM in conference room B.",
        "Your payment of {amount} to {name} was successful.",
        "Good morning! Don't forget the team standup at 10.",
        "I'll call you once I land, flight is on time.",
        "Your electricity bill for this month has been paid successfully.",
        "See you at the gym at 6, don't be late this time.",
    ]

    def fill(template):
        return template.format(
            bank=random.choice(banks),
            amount=random.choice(amounts),
            link=random.choice(links),
            name=random.choice(names),
            company=random.choice(companies),
        )

    rows = []
    for _ in range(n_per_class):
        rows.append({"label": "spam", "message": fill(random.choice(spam_templates))})
        rows.append({"label": "ham", "message": fill(random.choice(ham_templates))})

    df = pd.DataFrame(rows).drop_duplicates(subset="message").reset_index(drop=True)
    return df


def ensure_dataset() -> pd.DataFrame:
    DATASET_PATH.parent.mkdir(parents=True, exist_ok=True)
    if DATASET_PATH.exists():
        print(f"Loading existing dataset: {DATASET_PATH}")
        df = pd.read_csv(DATASET_PATH)
    else:
        print("No dataset found — generating a synthetic SMS dataset "
              "(replace dataset/sms_spam_dataset.csv with the real UCI "
              "SMS Spam Collection Dataset for production use).")
        df = generate_synthetic_dataset()
        df.to_csv(DATASET_PATH, index=False)
        print(f"Synthetic dataset saved to: {DATASET_PATH} ({len(df)} rows)")
    return df


# ---------------------------------------------------------------------------
# 2. Text cleaning
# ---------------------------------------------------------------------------
def clean_text(text: str) -> str:
    text = str(text).lower()
    text = re.sub(r"http\S+|www\.\S+", " URL ", text)
    text = re.sub(r"[^a-z0-9\s]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


# ---------------------------------------------------------------------------
# 3. Train, evaluate, save
# ---------------------------------------------------------------------------
def main():
    df = ensure_dataset()
    df["label"] = df["label"].str.strip().str.lower()
    df = df[df["label"].isin(["spam", "ham"])]
    df["clean_message"] = df["message"].apply(clean_text)

    X_train, X_test, y_train, y_test = train_test_split(
        df["clean_message"], df["label"], test_size=0.2, random_state=42, stratify=df["label"]
    )

    vectorizer = TfidfVectorizer(max_features=3000, ngram_range=(1, 2))
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    candidates = {
        "Logistic Regression": LogisticRegression(max_iter=1000),
        "Multinomial Naive Bayes": MultinomialNB(),
    }

    best_name, best_model, best_f1 = None, None, -1
    print("\n--- Model evaluation ---")
    for name, model in candidates.items():
        model.fit(X_train_vec, y_train)
        preds = model.predict(X_test_vec)

        acc = accuracy_score(y_test, preds)
        prec = precision_score(y_test, preds, pos_label="spam")
        rec = recall_score(y_test, preds, pos_label="spam")
        f1 = f1_score(y_test, preds, pos_label="spam")

        print(f"\n{name}")
        print(f"  Accuracy : {acc:.4f}")
        print(f"  Precision: {prec:.4f}")
        print(f"  Recall   : {rec:.4f}")
        print(f"  F1-score : {f1:.4f}")
        print(f"  Confusion matrix (rows=actual, cols=predicted, labels=[ham, spam]):")
        print(f"  {confusion_matrix(y_test, preds, labels=['ham', 'spam'])}")

        if f1 > best_f1:
            best_name, best_model, best_f1 = name, model, f1

    print(f"\nBest model: {best_name} (F1-score: {best_f1:.4f})")

    joblib.dump(best_model, MODEL_PATH)
    joblib.dump(vectorizer, VECTORIZER_PATH)
    print(f"\nSaved model to:      {MODEL_PATH}")
    print(f"Saved vectorizer to: {VECTORIZER_PATH}")
    print("\nDone. Restart app.py (or start it for the first time) to use the new model.")


if __name__ == "__main__":
    main()