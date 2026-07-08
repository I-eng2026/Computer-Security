import pandas as pd
import matplotlib.pyplot as plt
import os
from IPython.display import display
from tqdm import tqdm

# --- 1. Setup Environment ---
print("Setting up the environment...")
main_dir = './'
data_dir = './'
output_dir = './'

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
    df = df[:-1]
    display(f"[+] Finished reading CSV. Total rows: {len(df)}")
    return df


def topten_threat_actors(data: pd.DataFrame):
    display("Generating Graph 1: Top 10 Threat Actors by IP Address...")
    top_10_ips = data.groupby('source_ip').size().nlargest(10)

    plt.figure(figsize=(12, 6))
    top_10_ips.plot(kind='bar', color='skyblue')
    plt.title('Top 10 Threat Actors by IP Address', fontsize=16)
    plt.xlabel('Source IP Address', fontsize=12)
    plt.ylabel('Number of Attacks', fontsize=12)
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'top_10_threat_actors.png'))
    plt.close() # Close the plot to free up memory

    
# Graph 2: Top 10 Destination Ports with Descriptive Names
def topten_dest_port(data: pd.DataFrame):
    display("Generating Graph 2: Top 10 Targeted Destination Ports...")
    top_10_ports = data.groupby('destination_port').size().nlargest(10)

    port_names = {
        '21': 'FTP', '22': 'SSH', '23': 'Telnet', '25': 'SMTP', '53': 'DNS',
        '80': 'HTTP', '110': 'POP3', '143': 'IMAP', '443': 'HTTPS', '445': 'SMB',
        '3306': 'MySQL', '3389': 'RDP', '5900': 'VNC', '8080': 'HTTP Proxy'
    }
    port_labels = [f"{port} ({port_names.get(port, 'Unknown')})" for port in top_10_ports.index]

    plt.figure(figsize=(12, 8))
    top_10_ports.plot(kind='barh', color='coral')
    plt.title('Top 10 Targeted Destination Ports', fontsize=16)
    plt.xlabel('Number of Attacks', fontsize=12)
    plt.ylabel('Destination Port', fontsize=12)
    plt.yticks(range(len(port_labels)), port_labels)
    plt.gca().invert_yaxis()
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'top_10_destination_ports.png'))
    plt.close()

# Graph 3: Top 10 Communication Protocols
def topten_protocol(data: pd.DataFrame):
    display("Generating Graph 3: Top 10 Communication Protocols...")
    top_10_protocols = data.groupby('protocol').size().nlargest(10)
    plt.figure(figsize=(12, 6))
    top_10_protocols.plot(kind='bar', color='lightgreen')
    plt.title('Top 10 Communication Protocols Used in Attacks', fontsize=16)
    plt.xlabel('Protocol', fontsize=12)
    plt.ylabel('Number of Occurrences', fontsize=12)
    plt.xticks(rotation=0)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'top_10_protocols.png'))
    plt.close()

# Graph 4: Top 10 Ports Under Attack
def topten_portatk(data: pd.DataFrame):
    display("Generating Graph 4: Top 10 Ports Under Attack...")
    top_10_ports_attacked = data.groupby('destination_port').size().nlargest(10)
    plt.figure(figsize=(12, 6))
    top_10_ports_attacked.plot(kind='bar', color='gold')
    plt.title('Top 10 Ports Under Attack', fontsize=16)
    plt.xlabel('Destination Port Number', fontsize=12)
    plt.ylabel('Number of Attacks', fontsize=12)
    plt.xticks(rotation=0)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'top_10_ports_attacked.png'))
    plt.close()

if __name__ == "__main__":
    df = load_csv_with_progress(data_dir + "Honeypot_Sample_Log.csv")
    topten_dest_port(df)
    topten_protocol(df)
    topten_threat_actors(df)
    topten_portatk(df)

