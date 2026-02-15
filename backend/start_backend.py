import uvicorn
import os

if __name__ == "__main__":
    print("Starting Matrix Backend (NO RELOAD)...")
    # Run uvicorn with reload DISABLED to prevent infinite restart loops.
    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=8000,
        reload=False,  # <--- Core Fix: Disable auto-reload
        log_level="info"
    )
