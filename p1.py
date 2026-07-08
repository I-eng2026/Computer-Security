import numpy as np
import matplotlib.pyplot as plt  
import pandas as pd 
from tqdm import tqdm #necessary for helpful progress bar/debugging when working with large files
from IPython.display import display

data_dir = './'

def load_csv_with_progress(path: str, chunksize: int = 100_000) -> pd.DataFrame:
    """Reads a large TSV file in chunks with progress and returns a cleaned DataFrame."""
    display(f"[+] Reading CSV in chunks from: {path}")
    chunks = []
    total_lines = sum(1 for _ in open(path, 'r', encoding='utf8'))
    with tqdm(total=total_lines, desc="Loading CSV") as pbar:
        for chunk in pd.read_csv(path, sep='\t', encoding='utf8', dtype='string', chunksize=chunksize):
            chunks.append(chunk)
            pbar.update(len(chunk))
    df = pd.concat(chunks, ignore_index=True)
    # Drop the last row.
    df = df[:-1]
    display(f"[+] Finished reading CSV. Total rows: {len(df)}")
    return df

def topten_threat_actors()

if __name__ == "__main__":
    df = load_csv_with_progress(data_dir + "Honeypot_Sample_Log.csv")
    print(df)
