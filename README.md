# Computer Security

**CCPS 633 -- Toronto Metropolitan University**

Three projects covering practical cybersecurity topics: honeypot log analysis, multi-vector web threat detection, and NLP-based media bias analysis. Includes Jupyter notebooks for interactive exploration and standalone Python scripts.

## Projects

### Project 1 -- Honeypot Log Analysis

Processes and analyzes honeypot CSV log data to identify top threat actors, attack patterns, and source IP distributions.

### Project 2 -- Web Threat Detection Pipeline

A comprehensive threat detection engine that analyzes URLs and raw HTTP requests for multiple attack vectors:

- **SQL Injection** -- parallelized pattern matching across CPU cores
- **Cross-Site Scripting (XSS)** -- script tag and event handler detection
- **CSRF** -- header-based detection (missing tokens, origin/referer mismatches)
- **Directory Traversal** -- path traversal pattern recognition
- **Command Injection** -- shell metacharacter detection
- **Forceful Browsing** -- unauthorized endpoint access
- **DDoS** -- time-windowed request rate analysis per IP
- **Exploit Attempts** -- known payload signature matching

Outputs detailed and summary CSV reports.

### Project 3 -- NLP Media Bias Analysis

Reads documents (PDF, DOCX, TXT) and performs multi-stage analysis:

- Tokenization and lemmatization (spaCy)
- Named Entity Recognition with entity classification (WHO/WHERE/WHEN/WHAT)
- Sentiment polarity and subjectivity analysis (TextBlob)
- Bias signal detection and repetition analysis
- Data visualization (bar charts, scatter plots, histograms, pie charts)

## Technologies

- Python, Jupyter Notebooks
- **spaCy** (en_core_web_md) -- NLP pipeline
- **TextBlob** -- sentiment analysis
- **pandas / numpy** -- data processing
- **matplotlib / seaborn** -- visualization
- **pdfplumber / python-docx** -- document ingestion
- **joblib** -- parallel processing

## Setup

```bash
pip install -r requirements.txt
python -m spacy download en_core_web_md
```

## Running

```bash
# Standalone scripts
python p1.py    # Honeypot analysis
python p2.py    # Threat detection
python p3.py    # Bias analysis

# Or use the Jupyter notebooks for interactive exploration
jupyter notebook
```

## Project Structure

```
Computer-Security/
  requirements.txt          # Python dependencies
  p1.py / p2.py / p3.py   # Standalone project scripts
  *.ipynb                   # Jupyter notebooks
  t.py                      # Honeypot visualization
```
