import spacy
from spacy.tokens.doc import Doc
from spacy.util import minibatch
from spacy.training.example import Example
from textblob import TextBlob
import pandas as pd
from docx import Document
import pdfplumber
import os
from collections import Counter
from dateutil.parser import parse as parse_date
import re
import numpy as np
import seaborn as sns
from IPython.display import display
from spacy.lang.en.stop_words import STOP_WORDS
from matplotlib import pyplot as plt

def clean_text(doc:Doc) -> str:
    """Return a lemmatized and lowercased string without stopwords or punctuation."""
    display("Cleaning text...")
    return " ".join([token.lemma_.lower() for token in doc if not token.is_stop and token.is_alpha])

def tokenize(doc:Doc) -> list:
    """Return a list of lemmatized lowercase tokens excluding punctuation and spaces."""
    display("Tokenizing text...")
    return [token.lemma_.lower() for token in doc if not token.is_punct and not token.is_space]

def smp(text:str) -> float:
    """Return sentiment polarity score of the input text using TextBlob."""
    display("Calculating sentiment polarity...")
    blob = TextBlob(text)
    return blob.sentiment.polarity

def sms(text:str) -> float:
    """Return sentiment subjectivity score of the input text using TextBlob."""
    display("Calculating sentiment subjectivity...")
    blob = TextBlob(text)
    return blob.sentiment.subjectivity

def ner(ents:tuple) -> set[tuple]:
    """Extract named entities and their labels from spaCy Doc object."""
    display("Extracting named entities...")
    return set((ent.text.lower().strip(), ent.label_) for ent in ents)

def classify_entities(entities: list[tuple[str, str]]) -> dict:
    """Classify named entities into WHO, WHERE, WHEN, WHAT categories."""
    display("Classifying named entities...")
    role_map = {
        "WHO": {"PERSON", "ORG", "NORP"},
        "WHERE": {"GPE", "LOC", "FAC"},
        "WHEN": {"DATE", "TIME"},
        "WHAT": {"EVENT", "PRODUCT", "LAW"},
    }
    grouped = {"WHO": [], "WHERE": [], "WHEN": [], "WHAT": [], "WHY": [], "HOW": []}
    
    for text, label in entities:
        for role, label_set in role_map.items():
            if label in label_set:
                grouped[role].append(text)
    return grouped

def detect_context(row: dict) -> str:
    """Analyze contextual entities and timeline in a document."""
    display("Detecting context...")
    notes = []
    classified_ne = classify_entities(row["named_entities"])

    who = classified_ne.get("WHO", [])
    where = classified_ne.get("WHERE", [])
    when = classified_ne.get("WHEN", [])
    what = classified_ne.get("WHAT", [])

    # 1. Contextual summary notes
    if who:
        notes.append(f"Named actors mentioned include: {', '.join(who)}.\n")
    if where:
        notes.append(f"Geographic locations involved include: {', '.join(where)}.\n")
    if when:
        notes.append(f"Relevant dates referenced include: {', '.join(when)}.\n")
    if what:
        notes.append(f"Key topics or events discussed include: {', '.join(what)}.\n")

    return " ".join(notes)

def analyze_bias_signals(row: dict) -> str:
    """Evaluate bias signals based on sentiment, repetition, and moral framing."""
    display("Analyzing bias signals...")
    notes = []
    tokens = row["tokens"]
    text = row["text"]
    title = row["title"]
    named_entities = row["named_entities"]
    title_lower = title.lower()
    title_polarity, title_subjectivity = row["title_sentiment"]
    text_polarity = row["sentiment_polarity"]

    result = {
        "notes": notes,
        "top_tokens": [],
        "mfd_dominant": None
    }

    # === 1. Title subjectivity
    if title_subjectivity > 0.6:
        notes.append(f"The title appears highly subjective (subjectivity score: {title_subjectivity:.2f}), which may indicate sensationalized framing.")
    elif title_subjectivity < 0.3:
        notes.append(f"The title appears relatively objective (subjectivity score: {title_subjectivity:.2f}), suggesting a more neutral framing.")

    # === 2. Title sentiment intensity
    if abs(title_polarity) >= 0.5:
        tone = "positive" if title_polarity > 0 else "negative"
        notes.append(f"The title expresses a strong {tone} sentiment (polarity score: {title_polarity:.2f}).")
    elif abs(title_polarity) < 0.1:
        notes.append(f"The title is mostly neutral in tone (polarity score: {title_polarity:.2f}).")

    # === 3. Sentiment contrast between title and body
    polarity_diff = abs(title_polarity - text_polarity)
    if polarity_diff >= 0.4:
        notes.append(
            f"There is a significant difference between the title's sentiment (polarity {title_polarity:.2f}) "
            f"and the main text's sentiment (polarity {text_polarity:.2f}), which may reflect selective or misleading framing."
        )

    # === 4. Framing bias based on named entities in title
    classified_ne = classify_entities(named_entities)
    who = classified_ne.get("WHO", [])
    where = classified_ne.get("WHERE", [])
    when = classified_ne.get("WHEN", [])
    what = classified_ne.get("WHAT", [])

    geo_labels = {"ORG", "GPE", "NORP"}
    geo_entities = set([ent for ent, label in named_entities if label in geo_labels])

    if title_polarity < -0.1:
        if len(geo_entities) >= 2:
            notes.append("Multiple geopolitical or institutional actors are mentioned — this may suggest inter-state conflict or strategic tension.")
        for category, entities in {"WHO": who, "WHAT": what, "WHERE": where, "WHEN": when}.items():
            for ent in entities:
                if ent.lower() in title_lower:
                    notes.append(f"The {category.lower()} '{ent}' appears in a title with adverse sentiment, which may affect reader perception.")
    elif title_polarity > 0.1:
        if len(geo_entities) >= 2:
            notes.append("Multiple geopolitical or institutional actors are mentioned — this may indicate international collaboration, joint action, or shared strategic interests.")
        for category, entities in {"WHO": who, "WHAT": what, "WHERE": where, "WHEN": when}.items():
            for ent in entities:
                if ent.lower() in title_lower:
                    notes.append(f"The {category.lower()} '{ent}' appears in a title with favorable sentiment, which may shape reader interpretation positively.")

    # === 5. Repetition analysis (tokens and entities)
    filtered_tokens = [tok for tok in row["tokens"] if tok not in STOP_WORDS]
    token_counts = Counter(filtered_tokens)
    top_tokens = token_counts.most_common(10)
    result["top_tokens"] = top_tokens  # For visualizations

    # Add token-level repetition note
    repeated_str = ", ".join([f"{tok} ({count})" for tok, count in top_tokens if count > 4])
    if repeated_str:
        notes.append(f"The following terms are frequently repeated, indicating narrative emphasis: {repeated_str}.")

    # Named entity repetition (case insensitive)
    ner_counts = Counter(ent for ent, _ in named_entities)
    repeated_entities = [f"{k} ({v})" for k, v in ner_counts.items() if v > 3]
    if repeated_entities:
        notes.append(f"The following entities are repeatedly emphasized: {', '.join(repeated_entities)}.")

    return result

def detect_context(row: dict) -> str:
    display("Detecting context (with timeline)...")
    notes = []
    classified_ne = classify_entities(row["named_entities"])

    who = classified_ne.get("WHO", [])
    where = classified_ne.get("WHERE", [])
    when = classified_ne.get("WHEN", [])
    what = classified_ne.get("WHAT", [])

    # 1. Contextual summary notes
    if who:
        notes.append(f"Named actors mentioned include: {', '.join(who)}.")
    if where:
        notes.append(f"Geographic locations involved include: {', '.join(where)}.")
    if when:
        notes.append(f"Relevant dates referenced include: {', '.join(when)}.")
    if what:
        notes.append(f"Key topics or events discussed include: {', '.join(what)}.")

    # Timeline detection from date entities
    raw_dates = [ent for ent, label in row["named_entities"] if label == "DATE"]
    parsed_dates = []
    for d in raw_dates:
        try:
            if re.search(r'\d{4}|\d{2}', d):  # year or number indicator
                parsed = parse_date(d, fuzzy=True)
                if parsed:
                    # Convert to naive datetime by removing tzinfo
                    parsed = parsed.replace(tzinfo=None)
                    parsed_dates.append((d, parsed))
        except Exception:
            continue

    # Sort safely
    if parsed_dates:
        sorted_dates = sorted(parsed_dates, key=lambda x: x[1])
        if len(sorted_dates) >= 3:
            notes.append(
                f"The text refers to multiple dates, forming a narrative timeline from {sorted_dates[0][0]} to {sorted_dates[-1][0]}."
            )

    return " ".join(notes)

def section_labels(text:str, filename:str):
    """Label structural sections of the text based on heuristics."""
    display(f"Labeling sections for {filename}...")
    paragraphs = [p.strip() for p in text.split("\n") if p.strip()]
    filename_clean = filename.lower().replace("_", " ").replace(".docx", "")
    labeled_sections = []

    for i, para in enumerate(paragraphs):
        para_lower = para.lower()
        doc = nlp(para)
        num_sentences = len(list(doc.sents))

        labels = []
        
        if (para.istitle() or para.isupper() or filename_clean in para_lower) and len(para.split()) < 10:
            labels.append("TITLE")

        elif "author" in para_lower or para_lower.startswith("by "):
            labels.append("BYLINE")

        elif (num_sentences <= 1 and (para.count(":") >= 1 or para.count(".") >= 2) and len(para.split()) < 10):
            labels.append("METADATA")
            if "source:" in para_lower:
                labels.append("SOURCE")

            if any(k in para_lower for k in ["published", "updated", "date:"]):
                labels.append("PUBLISHED")

            if any(k in para_lower for k in ["copyright", "rights reserved"]):
                labels.append("FOOTNOTE")

        else:
            labels.append("BODY")

        labeled_sections.append((para, labels))

    return labeled_sections

def read_document(file:str) -> str:
    """Read and extract text from DOCX, PDF, or TXT files."""
    display(f"Reading document: {file}...")
    if file.endswith(".pdf"):
        with open(file, 'rb') as f:
            with pdfplumber.open(f) as pdf:
                text = ""
                for page in pdf.pages:
                    text += page.extract_text()
        return text

    if file.endswith(("doc", "docx")):
        doc = Document(file)
        full_text = []
        for para in doc.paragraphs:
            full_text.append(para.text)
        text = '\n'.join(full_text)
        return text

    if file.endswith("txt"):
        with open(file, 'r') as f:
            text =  f.read()
        return text

def load_data(data_dir: str) -> pd.DataFrame:
    """Load and process text documents into a structured DataFrame."""
    display("Loading and processing data...")
    data = os.listdir(data_dir)
    columns = [
        "title", "text", "cleaned_text", "tokens",
        "sentiment_polarity", "sentiment_subjectivity", "title_sentiment",
        "named_entities", "section_labels", 
        "context_notes", "general_sentiment", "top_tokens", "mfd_data"
    ]
    rows = []

    for file in data:
        if file.lower().endswith((".doc", ".docx", ".pdf", ".txt")):
            display(f"Processing file: {file}...")
            row = {}
            title = file.replace("_", " ").replace(".docx", "").title()
            text = read_document(os.path.join(data_dir, file))
            doc = nlp(text)

            # Core preprocessing
            row["title"] = title
            row["text"] = text
            row["cleaned_text"] = clean_text(doc)
            row["tokens"] = tokenize(doc)
            row["named_entities"] = ner(doc.ents)

            # Sentiment
            row["sentiment_polarity"] = smp(text)
            row["sentiment_subjectivity"] = sms(text)
            row["title_sentiment"] = (smp(title), sms(title))

            #analysis
            row["context_notes"] = detect_context(row)
            bias_data = analyze_bias_signals(row)
            row["general_sentiment"] = "; ".join(bias_data["notes"])
            row["top_tokens"] = bias_data["top_tokens"]
            row["mfd_dominant"] = bias_data["mfd_dominant"]

            rows.append(row)

    return pd.DataFrame(rows, columns=columns)

def plot_bias_report(df):
    """
    Generate and display summary visualizations for bias report DataFrame.
    """
    display("Generating plots...")

    fig, axes = plt.subplots(2, 2, figsize=(16, 10))
    fig.suptitle("Bias and Sentiment Overview", fontsize=16)

    # Plot 1: Sentiment polarity vs subjectivity
    sns.scatterplot(
        data=df,
        x="sentiment_polarity",
        y="sentiment_subjectivity",
        hue="title",
        ax=axes[0, 0]
    )
    axes[0, 0].set_title("Text Sentiment Polarity vs Subjectivity")
    axes[0, 0].set_xlabel("Polarity")
    axes[0, 0].set_ylabel("Subjectivity")
    axes[0, 0].axvline(0, color='grey', linestyle='--')
    axes[0, 0].axhline(0.5, color='grey', linestyle='--')

    # Plot 2: Top tokens across all documents
    all_tokens = []
    for tokens in df["top_tokens"]:
        all_tokens.extend([tok for tok, count in tokens])
    token_freq = dict(Counter(all_tokens))
    token_items = sorted(token_freq.items(), key=lambda x: x[1], reverse=True)[:10]
    tokens, counts = zip(*token_items)
    sns.barplot(x=list(counts), y=list(tokens), ax=axes[0, 1])
    axes[0, 1].set_title("Top 10 Frequent Tokens")
    axes[0, 1].set_xlabel("Count")

    # Plot 4: Sentiment polarity histogram
    sns.histplot(df["sentiment_polarity"], bins=20, kde=True, ax=axes[1, 1], color='skyblue')
    axes[1, 1].set_title("Distribution of Sentiment Polarity")
    axes[1, 1].set_xlabel("Polarity")

    plt.tight_layout(rect=[0, 0.03, 1, 0.95])
    plt.show()

if __name__ == "__main__":
    # Remove annoying error
    pd.options.mode.chained_assignment = None  # default='warn'
    pd.set_option('display.max_rows', 30)
    pd.set_option('display.max_columns', None)
    pd.set_option('display.expand_frame_repr', False)
    pd.set_option('max_colwidth', None)
    data_dir = './'
    #picked en_core_md for a balance of performance and speed. 
    #en_core_web_trf would be best but more size requirement and slower 
    #en_core_web_sm might give extra work when it comes to NER 
    nlp = spacy.load("en_core_web_md")
    df = load_data(data_dir)
    # Drop verbose or redundant columns for clean CSV output
    columns_to_drop = ["text", "cleaned_text", "section_labels"]
    df = df.drop(columns=[col for col in columns_to_drop if col in df.columns])
    print(df)
    df.to_csv("./report.csv", index=False)
    plot_bias_report(df)
