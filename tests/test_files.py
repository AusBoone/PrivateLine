"""File upload and download tests.

These tests exercise the REST API endpoints responsible for handling file
attachments. They verify that uploads are stored correctly, downloads respect
authorization and retention rules, and that invalid requests fail gracefully.
Run with ``pytest``.
"""

import io
import base64
from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename

from backend.app import app, db
from backend.models import File, Message
from .conftest import register_user, login_user, decrypt_private_key, sign_content


def test_file_upload_download(client):
    """Uploading then downloading a file should return the original bytes."""
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
    """Only the sender or recipient should be able to download a file."""
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
    """Uploaded filenames should be sanitized to avoid directory traversal."""
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


def test_missing_mimetype_defaults_octet_stream(client):
    """Server should default to application/octet-stream when type is absent."""
    reg = register_user(client, "dora")
    pk = decrypt_private_key(reg)
    token = login_user(client, "dora").get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    fs = FileStorage(stream=io.BytesIO(b"bin"), filename="bin.dat")
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
        data={"content": b64, "recipient": "dora", "file_id": fid, "signature": sig},
        headers=headers,
    )
    resp = client.get(f"/api/files/{fid}", headers=headers)
    assert resp.headers["Content-Type"] == "application/octet-stream"


def test_invalid_file_field(client):
    """Sending a non-file under 'file' should be rejected."""
    register_user(client, "erin")
    token = login_user(client, "erin").get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    resp = client.post(
        "/api/files",
        data={"file": "notafile"},
        headers=headers,
        content_type="multipart/form-data",
    )
    assert resp.status_code == 400


def test_file_upload_too_large(client):
    """Uploads exceeding the maximum size should yield HTTP 413."""
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


def test_content_length_header_enforced(client):
    """Explicit ``Content-Length`` above the limit should yield HTTP 413."""
    import backend.resources as res

    register_user(client, "hank")
    token = login_user(client, "hank").get_json()["access_token"]
    # Manually craft a multipart request so we can control the Content-Length
    # header. The payload is ``MAX_FILE_SIZE + 1`` bytes to trigger rejection
    # before the server attempts to stream the body.
    boundary = "boundary123"
    file_bytes = b"x" * (res.MAX_FILE_SIZE + 1)
    body = (
        f"--{boundary}\r\n".encode()
        + b"Content-Disposition: form-data; name=\"file\"; filename=\"big.bin\"\r\n"
        + b"Content-Type: application/octet-stream\r\n\r\n"
        + file_bytes
        + f"\r\n--{boundary}--\r\n".encode()
    )
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Content-Length": str(len(body)),
    }
    resp = client.open("/api/files", method="POST", data=body, headers=headers)
    assert resp.status_code == 413


def test_missing_file_field(client):
    """Submitting no file should return HTTP 400."""
    register_user(client, "bob")
    token = login_user(client, "bob").get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    resp = client.post(
        "/api/files", data={}, headers=headers, content_type="multipart/form-data"
    )
    assert resp.status_code == 400


def test_max_file_size_env(monkeypatch, client):
    """Lowering MAX_FILE_SIZE via env variable should reject larger uploads."""
    import backend.resources as res
    monkeypatch.setattr(res, "MAX_FILE_SIZE", 10)

    register_user(client, "carla")
    token = login_user(client, "carla").get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    big = io.BytesIO(b"a" * 11)
    fs = FileStorage(stream=big, filename="tiny.bin", content_type="application/octet-stream")
    resp = client.post(
        "/api/files", data={"file": fs}, headers=headers, content_type="multipart/form-data"
    )
    assert resp.status_code == 413


def test_file_removed_with_message(client):
    """Uploaded files should be deleted when the only referencing message is removed."""
    reg = register_user(client, "zoe")
    pk = decrypt_private_key(reg)
    token = login_user(client, "zoe").get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    fs = FileStorage(stream=io.BytesIO(b"bye"), filename="bye.txt", content_type="text/plain")
    resp = client.post(
        "/api/files", data={"file": fs}, headers=headers, content_type="multipart/form-data"
    )
    fid = resp.get_json()["file_id"]

    b64 = base64.b64encode(b"msg").decode()
    sig = sign_content(pk, b64)
    resp = client.post(
        "/api/messages",
        data={"content": b64, "recipient": "zoe", "file_id": fid, "signature": sig},
        headers=headers,
    )
    mid = resp.get_json()["id"]

    resp = client.delete(f"/api/messages/{mid}", headers=headers)
    assert resp.status_code == 200

    with app.app_context():
        assert db.session.get(File, fid) is None


def test_old_files_pruned(client):
    """Files past their retention period should be deleted and detached."""
    reg = register_user(client, "irene")
    pk = decrypt_private_key(reg)
    token = login_user(client, "irene").get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    fs = FileStorage(stream=io.BytesIO(b"expired"), filename="exp.txt")
    resp = client.post(
        "/api/files", data={"file": fs}, headers=headers, content_type="multipart/form-data"
    )
    fid = resp.get_json()["file_id"]

    b64 = base64.b64encode(b"msg").decode()
    sig = sign_content(pk, b64)
    resp = client.post(
        "/api/messages",
        data={"content": b64, "recipient": "irene", "file_id": fid, "signature": sig},
        headers=headers,
    )
    mid = resp.get_json()["id"]

    # Expire this file immediately by lowering its retention value to zero
    with app.app_context():
        rec = db.session.get(File, fid)
        rec.file_retention_days = 0
        db.session.commit()

    from backend.app import clean_expired_files

    clean_expired_files()

    with app.app_context():
        assert db.session.get(File, fid) is None
        assert db.session.get(Message, mid).file_id is None


def test_file_download_not_found(client):
    """Requesting a missing file id should yield HTTP 404."""
    register_user(client, "nina")
    token = login_user(client, "nina").get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    resp = client.get("/api/files/999", headers=headers)
    assert resp.status_code == 404


def test_recent_files_preserved(client):
    """Files newer than the retention period should remain available."""
    reg = register_user(client, "jane")
    pk = decrypt_private_key(reg)
    token = login_user(client, "jane").get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    fs = FileStorage(stream=io.BytesIO(b"keep"), filename="keep.txt")
    resp = client.post(
        "/api/files", data={"file": fs}, headers=headers, content_type="multipart/form-data"
    )
    fid = resp.get_json()["file_id"]

    b64 = base64.b64encode(b"hi").decode()
    sig = sign_content(pk, b64)
    resp = client.post(
        "/api/messages",
        data={"content": b64, "recipient": "jane", "file_id": fid, "signature": sig},
        headers=headers,
    )
    mid = resp.get_json()["id"]

    from backend.app import clean_expired_files

    clean_expired_files()

    with app.app_context():
        assert db.session.get(File, fid) is not None
        assert db.session.get(Message, mid).file_id == fid


def test_file_deleted_after_single_download(client):
    """A file with ``max_downloads=1`` should disappear after one retrieval."""
    reg = register_user(client, "max1")
    pk = decrypt_private_key(reg)
    token = login_user(client, "max1").get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    fs = FileStorage(stream=io.BytesIO(b"bye"), filename="bye.txt")
    resp = client.post(
        "/api/files", data={"file": fs}, headers=headers, content_type="multipart/form-data"
    )
    fid = resp.get_json()["file_id"]

    b64 = base64.b64encode(b"x").decode()
    sig = sign_content(pk, b64)
    resp = client.post(
        "/api/messages",
        data={"content": b64, "recipient": "max1", "file_id": fid, "signature": sig},
        headers=headers,
    )
    mid = resp.get_json()["id"]

    resp = client.get(f"/api/files/{fid}", headers=headers)
    assert resp.status_code == 200

    with app.app_context():
        assert db.session.get(File, fid) is None
        assert db.session.get(Message, mid).file_id is None

    resp = client.get(f"/api/files/{fid}", headers=headers)
    assert resp.status_code == 404


def test_file_deleted_after_custom_download_limit(client):
    """Files remain until the configured ``max_downloads`` threshold."""
    reg = register_user(client, "max2")
    pk = decrypt_private_key(reg)
    token = login_user(client, "max2").get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    fs = FileStorage(stream=io.BytesIO(b"hold"), filename="hold.txt")
    resp = client.post(
        "/api/files", data={"file": fs}, headers=headers, content_type="multipart/form-data"
    )
    fid = resp.get_json()["file_id"]

    b64 = base64.b64encode(b"msg").decode()
    sig = sign_content(pk, b64)
    resp = client.post(
        "/api/messages",
        data={"content": b64, "recipient": "max2", "file_id": fid, "signature": sig},
        headers=headers,
    )
    mid = resp.get_json()["id"]

    # Increase allowed downloads to two
    with app.app_context():
        rec = db.session.get(File, fid)
        rec.max_downloads = 2
        db.session.commit()

    resp = client.get(f"/api/files/{fid}", headers=headers)
    assert resp.status_code == 200
    with app.app_context():
        assert db.session.get(File, fid) is not None
        assert db.session.get(File, fid).download_count == 1

    resp = client.get(f"/api/files/{fid}", headers=headers)
    assert resp.status_code == 200
    with app.app_context():
        assert db.session.get(File, fid) is None
        assert db.session.get(Message, mid).file_id is None


def test_unauthorized_file_id_rejected(client):
    """Reusing another user's file ID should yield HTTP 403."""

    # Alice uploads a file and sends it to Bob so the file becomes associated
    # with her account.
    reg_a = register_user(client, "alice")
    pk_a = decrypt_private_key(reg_a)
    register_user(client, "bob")
    reg_c = register_user(client, "carol")
    pk_c = decrypt_private_key(reg_c)

    token_a = login_user(client, "alice").get_json()["access_token"]
    headers_a = {"Authorization": f"Bearer {token_a}"}
    token_c = login_user(client, "carol").get_json()["access_token"]
    headers_c = {"Authorization": f"Bearer {token_c}"}

    fs = FileStorage(stream=io.BytesIO(b"steal"), filename="steal.txt")
    resp = client.post(
        "/api/files",
        data={"file": fs},
        headers=headers_a,
        content_type="multipart/form-data",
    )
    fid = resp.get_json()["file_id"]

    b64 = base64.b64encode(b"hi").decode()
    sig_a = sign_content(pk_a, b64)
    client.post(
        "/api/messages",
        data={"content": b64, "recipient": "bob", "file_id": fid, "signature": sig_a},
        headers=headers_a,
    )

    b64_c = base64.b64encode(b"hack").decode()
    sig_c = sign_content(pk_c, b64_c)
    resp = client.post(
        "/api/messages",
        data={"content": b64_c, "recipient": "alice", "file_id": fid, "signature": sig_c},
        headers=headers_c,
    )
    assert resp.status_code == 403

    # Only Alice's message should exist; Carol's attempt is rejected.
    with app.app_context():
        assert Message.query.count() == 1


