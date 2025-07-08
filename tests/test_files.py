"""File upload and download tests."""

import io
import base64
from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename

from backend.app import app, db
from backend.models import File, Message
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

