import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

try:
    logging.info("Loading dataset...")
    data = pd.read_csv("phishing_dataset.csv")
    logging.info("Dataset loaded successfully!")
    
    logging.info("Columns in dataset: %s", data.columns)
    
    logging.info("Class Distribution:")
    logging.info(data["label"].value_counts())
    
    X = data.drop("label", axis=1)
    y = data["label"]
    
    logging.info("Splitting data into training and testing sets...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    logging.info("Data split completed!")
    
    logging.info("Training model...")
    model = RandomForestClassifier(random_state=42)
    model.fit(X_train, y_train)
    logging.info("Model trained successfully!")
    
    y_pred = model.predict(X_test)
    logging.info("\nPredictions: %s", y_pred)
    logging.info("\nConfusion Matrix:")
    logging.info(confusion_matrix(y_test, y_pred))
    logging.info("\nClassification Report:")
    logging.info(classification_report(y_test, y_pred))
    
    logging.info("\nPerforming cross-validation...")
    cv_scores = cross_val_score(model, X, y, cv=5)
    logging.info("Cross-validation scores: %s", cv_scores)
    logging.info("Mean cross-validation score: %s", cv_scores.mean())
    
    importances = model.feature_importances_
    feature_names = X.columns
    feature_importance_df = pd.DataFrame({"Feature": feature_names, "Importance": importances})
    logging.info("\nFeature Importance:")
    logging.info(feature_importance_df.sort_values(by="Importance", ascending=False))
    
    logging.info("\nSaving model...")
    joblib.dump(model, "phishing_url_detector.pkl")
    logging.info("Model saved as phishing_url_detector.pkl")

except FileNotFoundError:
    logging.error("Error: The dataset file 'phishing_dataset.csv' was not found. Please check the file path.")
except KeyError as e:
    logging.error(f"Error: The column '{e.args[0]}' does not exist in the dataset. Please check the column names.")
except Exception as e:
    logging.error(f"An unexpected error occurred: {e}")