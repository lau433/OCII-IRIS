<<<<<<< HEAD
import requests
r = requests.post(
    "http://ollama:11434/api/generate",
    json={"model": "llama3.1:8b", "prompt": "Dis juste OK", "stream": False},
    timeout=60
)
print(r.status_code)
=======
import requests
r = requests.post(
    "http://ollama:11434/api/generate",
    json={"model": "llama3.1:8b", "prompt": "Dis juste OK", "stream": False},
    timeout=60
)
print(r.status_code)
>>>>>>> d720f2b6649172b6438eed3b49b13a24f226495e
print(r.json().get("response", "")[:200])