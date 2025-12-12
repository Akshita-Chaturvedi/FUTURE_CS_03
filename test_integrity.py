# test_integrity.py
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
        print("usage: python test_integrity.py <local-file-to-test>")
        sys.exit(1)

    path = sys.argv[1]
    print("Uploading", path)

    code, _ = upload_file(path)
    if code not in (200, 302):
        print("Upload failed", code)
        sys.exit(2)

    files = list_files()
    fid = files[0]['id']  # newest file first

    print("Downloading id", fid)

    ok, err = download_file(fid, "/tmp/download_test")
    if not ok:
        print("Download failed:", err)
        sys.exit(3)

    with open(path, "rb") as a, open("/tmp/download_test", "rb") as b:
        h1 = hashlib.sha256(a.read()).hexdigest()
        h2 = hashlib.sha256(b.read()).hexdigest()

    print("Original sha256:", h1)
    print("Downloaded sha256:", h2)
    print("MATCH" if h1 == h2 else "MISMATCH")

