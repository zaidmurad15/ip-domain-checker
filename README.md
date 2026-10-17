# IP / Domain Checker

A Python command-line tool that checks whether an IP address or a domain is malicious, using the [VirusTotal API](https://www.virustotal.com/).

## Features
- Automatically detects whether the input is an IP address or a domain
- Queries the VirusTotal API v3 and prints the number of malicious and harmless detections
- Handles common errors: invalid API key (401), target not found (404), and network failures
- Keeps the API key out of the source code using a `.env` file

## Requirements
- Python 3.8+
- A free VirusTotal API key

## Setup
1. Clone the repository:
   `git clone https://github.com/zaidmurad15/ip-domain-checker.git`
2. Install dependencies:
   `pip install -r requirements.txt`
3. Create a `.env` file in the project folder (see `.env.example`):
   `VIRUSTOTAL_API_KEY=your_key_here`

## Usage
`python main.py 8.8.8.8`
`python main.py google.com`

## Example output
[Paste a screenshot or your real output here]

## Tech
Python, Requests, python-dotenv, argparse, VirusTotal REST API

## Status
Work in progress. Planned: input validation, more detection details, saving results to a file.
