import requests, hashlib, sys

BASE = "http://127.0.0.1:5000"

def sha256_bytes(b):
    h = hashlib.sha256()
    h.update(b)
    return h.hexdigest()

def upload_file(path):
    with open(path, "rb") as f:
        files = {"file": (path, f)}
        r = requests.post(BASE + "/upload", files=files, allow_redirects=False)
    return r.status_code, r.text

def list_files():
    r = requests.get(BASE + "/api/files")
    return r.json()

def download_file(file_id, out):
    r = requests.get(BASE + f"/download/{file_id}")
    if r.status_code != 200:
        return False, r.text
    with open(out, "wb") as f:
        f.write(r.content)
    return True, None

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: python test_integrity.py <original-file-path>")
        sys.exit(1)

    path = sys.argv[1]

    print("Uploading:", path)
    code, resp = upload_file(path)
    if code not in (200, 302):
        print("Upload failed:", code, resp)
        sys.exit(2)

    files = list_files()
    if not files:
        print("No files found on server.")
        sys.exit(3)

    latest = files[0]
    fid = latest['id']
    print("Downloading file ID:", fid)

    out_path = "download_testfile"
    ok, err = download_file(fid, out_path)
    if not ok:
        print("Download failed:", err)
        sys.exit(4)

    print("Comparing SHA256...")

    with open(path, "rb") as f1, open(out_path, "rb") as f2:
        h1 = sha256_bytes(f1.read())
        h2 = sha256_bytes(f2.read())

    print("Original SHA256 :", h1)
    print("Downloaded SHA256:", h2)

    if h1 == h2:
        print("MATCH ✔️ Encryption/Decryption successful!")
    else:
        print("MISMATCH ❌ Something is wrong.")
