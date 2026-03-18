import sys
import json
import requests

# Local Ollama endpoint - Your RTX 4070 will handle this easily
OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "llama3.1:8b" # Or "mranv/siem-llama-3.1" if pulled

def analyze_log(log_entry):
    system_prompt = (
        "You are a Senior Security Analyst. Analyze the provided log for malicious intent.\n"
        "Return the following fields strictly:\n"
        "1. VERDICT (True Positive / False Positive)\n"
        "2. THREAT LEVEL (1-10)\n"
        "3. SUMMARY (Max 2 sentences)\n"
        "4. REMEDIATION (One clear step)"
    )
    
    payload = {
        "model": MODEL,
        "prompt": f"{system_prompt}\n\nLOG DATA: {log_entry}",
        "stream": False
    }
    
    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=30)
        return response.json().get('response', 'Error: No AI response')
    except Exception as e:
        return f"System Error: {str(e)}"

if __name__ == "__main__":
    # Test with a manual string or piped input
    test_log = "Feb 23 14:12:01 republic-poly-vm sshd[1234]: Failed password for root from 192.168.1.50 port 22 ssh2"
    print("--- AI TRIAGE REPORT ---")
    print(analyze_log(test_log))