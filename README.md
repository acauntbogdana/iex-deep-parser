# IEX DEEP Parser

High-speed `pcap.gz` → `Parquet` converter for IEX DEEP 1.0 market data.  
Includes automatic download from Google Cloud Storage and a multi-threaded processing pipeline.

## Requirements
- Python 3.8+ (for the pipeline)
- Rust (cargo) to compile the parser
- Internet access to download the raw data

## Installation & Build
```bash
# Clone the repository
git clone https://github.com/acauntbogdana/iex-deep-parser.git
cd iex-deep-parser

# Set up a virtual environment and install Python dependencies
python -m venv .venv
.venv\Scripts\activate      # Windows
# source .venv/bin/activate  # Linux/Mac
pip install -r requirements.txt

# Build the Rust parser
cd iex_deep_parser
cargo build --release
cd ..
