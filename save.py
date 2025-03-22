import pandas as pd

# Sample data
data = {
    "url_length": [20, 50, 30, 40, 25],
    "https": [1, 0, 1, 0, 1],
    "special_chars": [2, 5, 3, 4, 1],
    "domain_age": [365, 10, 100, 50, 200],
    "label": [0, 1, 0, 1, 0]
}

# Create a DataFrame
df = pd.DataFrame(data)

# Save the DataFrame as a CSV file
file_path = r"C:\Users\Aditya\OneDrive\Desktop\New folder (2)\project 1\phishing_dataset.csv"
df.to_csv(file_path, index=False)

print(f"Dataset saved successfully at {file_path}")