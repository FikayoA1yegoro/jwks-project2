from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3
import time


hostName = "localhost"
serverPort = 8080

conn = sqlite3.connect("totally_not_my_privateKeys.db", check_same_thread=False)
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)
""")
conn.commit()


def generate_private_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )


def pem_bytes_from_private_key(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )


def load_private_key_from_pem(pem_data):
    return serialization.load_pem_private_key(pem_data, password=None)


def int_to_base64(value):
    value_hex = format(value, "x")
    if len(value_hex) % 2 == 1:
        value_hex = "0" + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b"=")
    return encoded.decode("utf-8")


def seed_keys():
    cursor.execute("SELECT COUNT(*) FROM keys")
    count = cursor.fetchone()[0]

    if count == 0:
        expired_key = generate_private_key()
        valid_key = generate_private_key()

        expired_pem = pem_bytes_from_private_key(expired_key)
        valid_pem = pem_bytes_from_private_key(valid_key)

        expired_exp = int(time.time()) - 3600
        valid_exp = int(time.time()) + 3600

        cursor.execute(
            "INSERT INTO keys (key, exp) VALUES (?, ?)",
            (expired_pem, expired_exp)
        )
        cursor.execute(
            "INSERT INTO keys (key, exp) VALUES (?, ?)",
            (valid_pem, valid_exp)
        )
        conn.commit()


def get_signing_key(expired=False):
    now = int(time.time())

    if expired:
        cursor.execute(
            "SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1",
            (now,)
        )
    else:
        cursor.execute(
            "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1",
            (now,)
        )

    row = cursor.fetchone()
    if row is None:
        return None

    kid, pem_data, exp = row
    private_key = load_private_key_from_pem(pem_data)

    return {
        "kid": str(kid),
        "private_key": private_key,
        "exp": exp
    }


def build_jwk_from_private_key(private_key, kid):
    numbers = private_key.private_numbers()
    return {
        "alg": "RS256",
        "kty": "RSA",
        "use": "sig",
        "kid": str(kid),
        "n": int_to_base64(numbers.public_numbers.n),
        "e": int_to_base64(numbers.public_numbers.e),
    }


seed_keys()


class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        if parsed_path.path == "/auth":
            use_expired = "expired" in params
            key_record = get_signing_key(expired=use_expired)

            if key_record is None:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"No suitable key found in database")
                return

            headers = {
                "kid": key_record["kid"]
            }

            if use_expired:
                token_exp = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
            else:
                token_exp = datetime.datetime.utcnow() + datetime.timedelta(hours=1)

            token_payload = {
                "user": "userABC",
                "exp": token_exp
            }

            private_pem = key_record["private_key"].private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )

            encoded_jwt = jwt.encode(
                token_payload,
                private_pem,
                algorithm="RS256",
                headers=headers
            )

            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return

        self.send_response(405)
        self.end_headers()

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            now = int(time.time())
            cursor.execute(
                "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp ASC",
                (now,)
            )
            rows = cursor.fetchall()

            jwk_list = []
            for kid, pem_data, exp in rows:
                private_key = load_private_key_from_pem(pem_data)
                jwk_list.append(build_jwk_from_private_key(private_key, kid))

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()

            keys = {"keys": jwk_list}
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()


if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        webServer.server_close()
        conn.close()