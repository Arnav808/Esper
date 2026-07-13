# 🛡️ Esper

Esper is an AI-powered web security analysis tool that performs passive security scans, generates a website security score, provides AI-powered insights using Google Gemini, and automatically creates a downloadable Markdown security report.

## ✨ Features

* 🔍 Passive website security analysis
* 📊 Website security scoring & analytics
* 🤖 AI-powered analysis using Google Gemini
* 📝 Automatic Markdown report generation

## 🛠️ Tech Stack

* Python
* Flask
* Google Gemini API
* Requests

## 🚀 Installation

Clone the repository:

```bash
git clone https://github.com/Arnav808/Esper.git
cd Esper
```

Install the required packages:

```bash
pip install -r requirements.txt
```

Create a `.env` file in the project root and add your Gemini API key:

```env
GOOGLE_API_KEY=your_api_key_here
```

Start the Flask server:

```bash
python app.py
```

## 📖 How to Use

1. Start the Flask server:

```bash
python app.py
```

2. Open a new terminal and send a POST request to the `/scan` endpoint:

```bash
curl -X POST http://localhost:5000/scan \
-H "Content-Type: application/json" \
-d '{"url":"https://github.com"}'
```

3. Esper will automatically:

* Perform a passive security scan.
* Calculate a website security score.
* Generate AI-powered security insights using Google Gemini.
* Create a Markdown report in the `reports/` directory.

### Example Response

```json
{
  "score": 88,
  "status": "Completed",
  "report": "reports/github_report.md"
}
```

## 📂 Project Structure

```text
Esper/
├── ai/                # Gemini AI integration
├── analysis/          # Scoring & analytics
├── scanners/          # Security scanners
├── exporters/         # Markdown report generator
├── reports/           # Generated reports
├── app.py             # Flask application
└── requirements.txt
```

## 🛣️ Roadmap

* Add more security scanners
* Interactive dashboard
* PDF report generation
* Expanded OWASP Top 10 checks

## 👤 Author

**Arnav Srivastava**

GitHub: https://github.com/Arnav808/Esper
