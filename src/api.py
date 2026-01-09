from fastapi import FastAPI

app = FastAPI()

@app.get("/health")
def health_check():
    return {"status": "ok", "mode": "standalone", "message": "Online features have been disabled."}

@app.get("/sub/{token}")
def get_subscription(token: str):
    return {"error": "Online features disabled"}
