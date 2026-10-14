"""Requests must use one access/refresh token generation throughout signing."""

import hashlib
import time
import unittest
from unittest.mock import Mock, patch

from tuya_sharing import customerapi


class TokenSnapshotTest(unittest.TestCase):
    def test_refresh_during_encryption_keeps_signature_and_header_consistent(self):
        old = customerapi.CustomerTokenInfo({
            "t": int(time.time() * 1000), "expire_time": 3600,
            "access_token": "old-access", "refresh_token": "old-refresh",
        })
        new = customerapi.CustomerTokenInfo({
            "t": int(time.time() * 1000), "expire_time": 3600,
            "access_token": "new-access", "refresh_token": "new-refresh",
        })
        api = customerapi.CustomerApi(old, "client", "user", "https://example.invalid", None)
        response = Mock(ok=True)
        response.json.return_value = {"success": True}
        api.session.request = Mock(return_value=response)
        encrypt = customerapi._aes_gcm_encrypt

        def rotate(raw, secret):
            # The refresh worker publishes a new pair while this request is
            # encrypting its payload, after deriving the old pair's key.
            api.token_info = new
            return encrypt(raw, secret)

        with patch.object(customerapi, "_aes_gcm_encrypt", side_effect=rotate):
            self.assertEqual(api.post("/scene", body={"sceneId": "test"}), {"success": True})
        request = api.session.request.call_args.kwargs
        headers = request["headers"]
        self.assertEqual(headers["X-token"], old.access_token)
        key = hashlib.md5((headers["X-requestId"] + old.refresh_token).encode()).hexdigest()
        self.assertEqual(headers["X-sign"], customerapi._restful_sign(
            key, "", request["json"]["encdata"], headers,
        ))
        self.assertIs(api.token_info, new)

    def test_request_after_refresh_uses_new_pair(self):
        old = customerapi.CustomerTokenInfo({"access_token": "old", "refresh_token": "old"})
        new = customerapi.CustomerTokenInfo({"access_token": "new", "refresh_token": "new"})
        api = customerapi.CustomerApi(old, "client", "user", "https://example.invalid", None)
        api.refresh_access_token_if_need = lambda: setattr(api, "token_info", new)
        response = Mock(ok=True)
        response.json.return_value = {"success": True}
        api.session.request = Mock(return_value=response)
        api.get("/devices")
        headers = api.session.request.call_args.kwargs["headers"]
        self.assertEqual(headers["X-token"], new.access_token)
        key = hashlib.md5((headers["X-requestId"] + new.refresh_token).encode()).hexdigest()
        self.assertEqual(headers["X-sign"], customerapi._restful_sign(key, "", "", headers))
