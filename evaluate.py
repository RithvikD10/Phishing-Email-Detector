from __future__ import annotations

from pathlib import Path

import joblib
import matplotlib.pyplot as plt
import pandas as pd
from sklearn.metrics import ConfusionMatrixDisplay, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

BASE_DIR = Path(__file__).resolve().parent
DATA_PATH = BASE_DIR / "data" / "training_data.csv"
MODEL_PATH = BASE_DIR / "models" / "phishing_model.joblib"
ASSET_PATH = BASE_DIR / "assets" / "confusion_matrix.png"


def main() -> None:
    frame = pd.read_csv(DATA_PATH)
    _, X_test, _, y_test = train_test_split(
        frame["text"],
        frame["label"],
        test_size=0.25,
        random_state=42,
        stratify=frame["label"],
    )

    pipeline = joblib.load(MODEL_PATH)
    predictions = pipeline.predict(X_test)

    matrix = confusion_matrix(y_test, predictions)
    disp = ConfusionMatrixDisplay(confusion_matrix=matrix, display_labels=["Legit", "Phishing"])
    fig, ax = plt.subplots(figsize=(6, 5))
    disp.plot(ax=ax, colorbar=False)
    ax.set_title("Confusion Matrix")
    plt.tight_layout()
    fig.savefig(ASSET_PATH, dpi=160)
    plt.close(fig)

    print(classification_report(y_test, predictions, target_names=["legit", "phishing"]))
    print(f"Saved confusion matrix to {ASSET_PATH}")


if __name__ == "__main__":
    main()
