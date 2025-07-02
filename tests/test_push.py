"""Push notification helper tests."""

import backend.resources as res


def test_fcm_request(monkeypatch):
    """An Android token should trigger a request to FCM."""
    called = {}

    def fake_post(url, json=None, headers=None, timeout=None):
        called['url'] = url
        called['json'] = json
        called['headers'] = headers
        return type('Resp', (), {'status_code': 200})

    monkeypatch.setenv('FCM_SERVER_KEY', 'secret')
    monkeypatch.setattr('requests.post', fake_post)

    res.send_fcm('token123', 'hi')

    assert called['url'] == 'https://fcm.googleapis.com/fcm/send'
    assert called['json']['to'] == 'token123'
    assert called['headers']['Authorization'] == 'key=secret'

