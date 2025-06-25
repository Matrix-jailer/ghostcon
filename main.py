from GhostAPIPRO import app  # ✅ match exact file name

if __name__ == "__main__":
    import uvicorn
    import os

    port = int(os.environ.get("PORT", 10000))
    uvicorn.run("GhostAPIPRO:app", host="0.0.0.0", port=port)
