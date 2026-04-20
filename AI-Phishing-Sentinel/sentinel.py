import sys
import json
import requests
import pandas as pd
import argparse
from datetime import datetime

class PhishingSentinel:
    def __init__(self, model="llama3"):
        self.model = model
        self.url = "http://localhost:11434/api/generate"

    def analyze_text(self, text):
        prompt = (
            "Analyze the following text for phishing indicators and social engineering tactics. "
            "Respond in structured JSON format with the following keys: "
            "'risk_score' (0-10), 'indicators' (list), 'reasoning' (brief string).\n\n"
            f"Text: {text}"
        )
        
        try:
            response = requests.post(self.url, json={
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "format": "json"
            }, timeout=15)
            response.raise_for_status()
            return json.loads(response.json()['response'])
        except Exception as e:
            return {"error": str(e), "risk_score": -1, "indicators": [], "reasoning": "Analysis failed."}

    def batch_process(self, input_csv, output_file=None):
        print(f"[*] Loading batch data from {input_csv}")
        df = pd.read_csv(input_csv)
        
        if 'text' not in df.columns:
            print("[!] Error: CSV must contain a 'text' column.")
            return

        results = []
        for index, row in df.iterrows():
            print(f"[*] Analyzing item {index+1}/{len(df)}...")
            analysis = self.analyze_text(row['text'])
            analysis['original_text'] = row['text']
            analysis['timestamp'] = datetime.now().isoformat()
            results.append(analysis)

        output_df = pd.DataFrame(results)
        
        if not output_file:
            output_file = f"phishing_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        output_df.to_json(output_file, orient='records', indent=4)
        print(f"[+] Batch analysis complete. Report saved to {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI Phishing Sentinel - Local Social Engineering Detection")
    parser.add_argument("--text", type=str, help="Single text snippet to analyze")
    parser.add_argument("--file", type=str, help="CSV file for batch processing (must have 'text' column)")
    parser.add_argument("--model", type=str, default="llama3", help="Ollama model to use (default: llama3)")
    
    args = parser.parse_args()
    sentinel = PhishingSentinel(model=args.model)

    if args.file:
        sentinel.batch_process(args.file)
    elif args.text:
        result = sentinel.analyze_text(args.text)
        print(json.dumps(result, indent=4))
    else:
        text = input("Enter text to analyze: ")
        result = sentinel.analyze_text(text)
        print(json.dumps(result, indent=4))
