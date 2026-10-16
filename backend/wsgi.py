"""
ScamShield Production WSGI Server Runner
Runs the Flask application using Waitress production server.
"""

import os
from waitress import serve
from app import app

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    host = os.environ.get("HOST", "127.0.0.1")
    threads = int(os.environ.get("THREADS", 4))
    
    print(f"========================================================")
    print(f"  SCAMSHIELD 2.0 PRODUCTION SERVER RUNNING (WAITRESS)  ")
    print(f"  Listening on: http://{host}:{port}                    ")
    print(f"  Worker Threads: {threads}                              ")
    print(f"========================================================")
    
    serve(app, host=host, port=port, threads=threads)
