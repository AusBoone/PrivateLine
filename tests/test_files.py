"""File upload and download tests."""

import io
import base64
from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename

from backend.app import app, db
from backend.models import File
from .conftest import register_user, login_user, decrypt_private_key, sign_content


def test_file_upload_download(client):
    reg = register_user(client, "alice")
    pk = decrypt_private_key(reg)
    token = login_user(client, "alice").get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Explicitly set the content type so the server records it for download
    fs = FileStorage(
        stream=io.BytesIO(b"hello"), filename="hello.txt", content_type="text/plain"
    )
    resp = client.post(
        "/api/files",
        data={"file": fs},
        headers=headers,
        content_type="multipart/form-data",
    )
    assert resp.status_code == 201
    fid = resp.get_json()["file_id"]

    msg_b64 = base64.b64encode(b"hi").decode()
    sig = sign_content(pk, msg_b64)
    client.post(
        "/api/messages",
        data={
            "content": msg_b64,
            "recipient": "alice",
            "file_id": fid,
            "signature": sig,
        },
        headers=headers,
    )

    resp = client.get(f"/api/files/{fid}", headers=headers)
    assert resp.status_code == 200
    assert resp.data == b"hello"
    # Download should preserve the original MIME type
    assert resp.headers["Content-Type"] == "text/plain"


def test_file_download_authorization(client):
    reg_a = register_user(client, "alice")
    pk_a = decrypt_private_key(reg_a)
    register_user(client, "bob")
    register_user(client, "carol")

    token_a = login_user(client, "alice").get_json()["access_token"]
    headers_a = {"Authorization": f"Bearer {token_a}"}

    fs = FileStorage(
        stream=io.BytesIO(b"secret"), filename="secret.txt", content_type="text/plain"
    )
    resp = client.post(
        "/api/files",
        data={"file": fs},
        headers=headers_a,
        content_type="multipart/form-data",
    )
    fid = resp.get_json()["file_id"]

    b64 = base64.b64encode(b"hi").decode()
    sig = sign_content(pk_a, b64)
    client.post(
        "/api/messages",
        data={"content": b64, "recipient": "bob", "file_id": fid, "signature": sig},
        headers=headers_a,
    )

    token_c = login_user(client, "carol").get_json()["access_token"]
    headers_c = {"Authorization": f"Bearer {token_c}"}
    resp = client.get(f"/api/files/{fid}", headers=headers_c)
    assert resp.status_code == 403


def test_filename_sanitization(client):
    reg = register_user(client, "alice")
    pk = decrypt_private_key(reg)
    token = login_user(client, "alice").get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    unsanitized = "../../evil.txt"
    fs = FileStorage(
        stream=io.BytesIO(b"data"), filename=unsanitized, content_type="text/plain"
    )
    resp = client.post(
        "/api/files",
        data={"file": fs},
        headers=headers,
        content_type="multipart/form-data",
    )
    assert resp.status_code == 201
    fid = resp.get_json()["file_id"]
    b64 = base64.b64encode(b"x").decode()
    sig = sign_content(pk, b64)
    client.post(
        "/api/messages",
        data={"content": b64, "recipient": "alice", "file_id": fid, "signature": sig},
        headers=headers,
    )
    expected = secure_filename(unsanitized)
    with app.app_context():
        assert db.session.get(File, fid).filename == expected
    resp = client.get(f"/api/files/{fid}", headers=headers)
    assert resp.status_code == 200
    cd = resp.headers["Content-Disposition"]
    assert f"filename={expected}" in cd


def test_file_upload_too_large(client):
    register_user(client, "alice")
    token = login_user(client, "alice").get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    big = io.BytesIO(b"x" * (5 * 1024 * 1024 + 1))
    fs = FileStorage(
        stream=big, filename="big.bin", content_type="application/octet-stream"
    )
    resp = client.post(
        "/api/files",
        data={"file": fs},
        headers=headers,
        content_type="multipart/form-data",
    )
    assert resp.status_code == 413
