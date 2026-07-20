from __future__ import annotations

import base64
import urllib.parse
import urllib.request


class SmsSink:
    def __init__(
        self,
        enabled: bool,
        account_sid: str,
        auth_token: str,
        from_number: str,
        to_number: str,
    ) -> None:
        self.enabled = enabled
        self.account_sid = account_sid.strip()
        self.auth_token = auth_token.strip()
        self.from_number = from_number.strip()
        self.to_number = to_number.strip()

    def send(self, message: str) -> tuple[int, str]:
        if not self.enabled:
            return (0, "sms disabled")

        if not all([self.account_sid, self.auth_token, self.from_number, self.to_number]):
            return (1, "sms config incomplete")

        url = f"https://api.twilio.com/2010-04-01/Accounts/{self.account_sid}/Messages.json"
        auth = base64.b64encode(f"{self.account_sid}:{self.auth_token}".encode("utf-8")).decode("ascii")
        data = urllib.parse.urlencode(
            {"From": self.from_number, "To": self.to_number, "Body": message}
        ).encode("utf-8")

        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Authorization", f"Basic {auth}")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return (0, f"http={resp.status}")
        except Exception as exc:  # noqa: BLE001
            return (2, str(exc))
