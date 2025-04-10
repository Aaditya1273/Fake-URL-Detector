# FAKE URL DETECTOR🕵️🎯

A modern web application that analyzes URLs to detect potential phishing attempts using machine learning and security features analysis.

## Features

- Modern UI with deep blue and purple color theme
- URL analysis for phishing detection
- Detailed security information display
- Real-time URL validation and suggestions
- Advanced error handling with helpful user feedback
- Responsive design for all devices

## Installation

1. Clone the repository
2. Install the required dependencies:

```bash
pip install -r requirements.txt
```

3. If you encounter dependency issues, particularly with `dnspython`, you can install it separately:

```bash
pip install dnspython==2.2.1
```

## How to Run

### Using the Full Application

Start the Flask application:

```bash
python app.py
```


### Using the Offline Demo Version

If you have issues with the Python dependencies or just want to see the UI in action:

1. Navigate to the `static` folder
2. Open `offline_demo.html` in your web browser

The offline demo provides a simulated experience of the application without requiring the server to be running.

## Troubleshooting

### Missing DNS Module

If you see an error like `ModuleNotFoundError: No module named 'dns'`, install the dnspython package:

```bash
pip install dnspython==2.2.1
```

### Invalid Escape Sequence Warning

You might see warnings about invalid escape sequences in regex patterns. These have been fixed in the latest version.

### Server Not Running

If you receive errors indicating that the server is not responding:

1. Check that you have all dependencies installed
2. Verify that the Flask application is running
3. Try using the offline demo version to see the UI

## Technologies Used

- Python Flask for the backend
- Bootstrap 5 for responsive layout
- Custom CSS for modern tech UI
- JavaScript for interactive features
- Machine learning for phishing detection

## License

This project is licensed under the MIT License - see the LICENSE file for details.


---

## 📌 Features

- 🔍 Detects phishing URLs using trained machine learning models
- 🧠 Utilizes advanced URL feature extraction techniques
- ⚙️ Simple, intuitive, and responsive web interface
- 📊 Displays prediction results and confidence score
- 🛠️ Built with Python Flask/Django and integrated with HTML/CSS/JS

---

## 🛠️ Tech Stack

- **Frontend:** HTML, CSS, JavaScript
- **Backend:** Python, Flask 
- **Machine Learning:**  Pandas, NumPy
- **Utilities:** Joblib 

---


