# Guardian-Log-Analyzer
AI-powered security log parser and anomaly detector using local LLMs.

## Overview
This script parses SSH auth logs and sends suspicious patterns to Ollama for an automated summary of potential security threats.

## Usage
1. Ensure Ollama is running locally with the `llama2` model.
2. Run the script:
   ```bash
   python analyzer.py sample_logs/auth.log
   ```
