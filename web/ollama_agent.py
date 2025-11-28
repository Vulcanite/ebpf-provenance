#!/usr/bin/env python3
"""Module to interact with Ollama LLM server"""

import requests

def query_ollama(prompt, model="llama3.2", host="http://localhost:11434"):
    """Send a query to Ollama and get response"""
    try:
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False
        }

        response = requests.post(
            f"{host}/api/generate",
            json=payload,
            timeout=60
        )

        # Check for errors
        if response.status_code == 404:
            try:
                error_detail = response.json()
            except:
                error_detail = response.text
            return f"Error 404: API endpoint not found\n\n**URL:** {response.url}\n**Response:** {error_detail}\n\n**Troubleshooting:**\n1. Verify Ollama is running: `ollama serve`\n2. Check if model exists: `ollama list`\n3. Pull the model if needed: `ollama pull {model}`\n4. Try using full model name with tag (e.g., 'llama3:latest' instead of 'llama3')"

        response.raise_for_status()
        result = response.json()
        return result.get("response", "No response from model")

    except requests.exceptions.HTTPError as e:
        try:
            error_body = e.response.json()
        except:
            error_body = e.response.text
        return f"HTTP Error {e.response.status_code}: {str(e)}\n\n**Response:** {error_body}"
    except requests.exceptions.ConnectionError:
        return f"Cannot connect to Ollama at {host}. Make sure Ollama is running.\n\nTry: `ollama serve`"
    except requests.exceptions.Timeout:
        return "Request timed out. The model might be too slow or the prompt too long."
    except Exception as e:
        return f"Unexpected error: {type(e).__name__}: {str(e)}"

def check_ollama_connection(host="http://localhost:11434"):
    """Check if Ollama is running and list available models"""
    try:
        response = requests.get(f"{host}/api/tags", timeout=5)
        response.raise_for_status()
        models = response.json().get("models", [])
        # Keep full model names with tags (e.g., llama3:latest)
        model_names = [m.get("name", "") for m in models]
        # Also provide simplified names without tags
        simplified = list(set([m.split(":")[0] for m in model_names]))
        return True, model_names, simplified
    except Exception:
        return False, [], []