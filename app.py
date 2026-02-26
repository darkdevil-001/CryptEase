from flask import Flask, render_template, request, redirect, url_for
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


app = Flask(__name__)

# Generate RSA keys on startup for demo use.
from Crypto.PublicKey import RSA

PRIVATE_KEY = b"""-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAlytGPmlMCfwilUcIQaP9sHLdIBDqNYFHK945RuI5EjjrjHRq
jWVLCSJ1iFkKE7LPHWQLMnBsBJ30GNOYVPZzl+ZXKFJM3n5O16QOspWHf9wIlW07
9Y3n16iuEtx9kNwkokld5AbNB+srb0RS4nrGKYHhuSv5uowfh4aLWufRjSanVAsx
w8XQeqEMKkXYluz+/l2Yq+mlM1lgyFnPBTwgTs/qpKBWSEyFVOygAnNvE6syCnxh
28dh8cQP17fxxAjid1Ta/gv9EH8xpktNn4Kce+WqYrdL69JBxhIoDTHQOa0T+cAE
gRoqgOZq1TYJlCdA3BXyM38p51NjA4eP7+Y7oQIDAQABAoIBAA7eVMRiuvXodMZV
/Dvok1U9lv5Ga6Ljmkp4Sw3rxk1Ch/iCotBRfDXjy8ejalhRqAluA6PsZtN1bcLb
XQpOS0RPhZcTsTfZGIwhOMjb6D3tOHLqEZGvaXROxQBZ64fJ/1hu+usouBXlTZpe
EADyrnb6rWb3KlLs4VUFKMPCNVw6oFvSPMlFyKKx2woaaK4OCefbwd2pnryBjgtd
QtPXoMI/yrWl9bPWfRPj/wdtePbsmWde/18zbx8kBMsZLOzVdIfvShkroDhuIfkY
1KVNR9Ni3NYqxUDg/YTh3M9UaA/sG+RJM2r9wUua1d1lH5Xpr8GPaCk93N3hbjHT
h4bLvoECgYEAxAOXE42ltIpVEFNMeYU/P5F/TbbLMR8T0WjgucbfjhId+xqYpaxG
TW1iFnjEDf9TEY37b5aavPV8zkvk99WyV9jrIq0OVgEIRNgD98vYKfvj6XCW8jW4
nY7QNXa4N/tKRpxb8utcT99e+QhvpBh0ZpEKFd7YZFSqfuj/GsUo28kCgYEAxW5f
6zzGW58uIQOimosEkLmcN/86FDQII7XCtMXZfUXOuvq2nllL12IOwAyQdzl0eFYL
SEi3eUbRJcf0BJL6vyVKbHF9AGp57WRyebk4BkqGEuAw5Qs9DRE8UgOkRbQsKZD5
9pJHkp08Fl4roSw4EYa7F6NxtXV/WLwupilrHRkCgYABLOhWBK5us7mo3GcD/4mO
jwfNZoA3bjFHOzLFymyCxJcLb3Bk5fCR/ErvSZAbaWGNJGXSmHubEHnMHuZjmhN0
tWdLkPAaEe2DxCvZ644DSnBmcPdmwm21/CpBd9HI/CfI3p0qisDF9dfy9Fr/B+qC
xvHhibGQgHV5R1poRbBmCQKBgGPsDe3P75CVitI4tcZDz8azuiX5LdrlzqzMJEQ7
0mx9tTibBWw1Q5Y50b9PXJqK4LC607D85KcjuVzGy3C5NuEhLX6fHaXlPdpxOSL0
JC/C7gKFpxl1S6veakoT/8MrgiJzdp9dv42ruKqVdL141NPB/dTj6vvtAMvXSkDc
u5KZAoGAXOpRCzUVku0w26TNuU8370NF4v1dcFBJu/aZFvTGqhPaMM5Z1chiLpQE
3U5TkSD+/CvvdGLzla318uJkELiUZ5dE//ylxdk2Bt72s+LF+aB3nGGhC8ndnwtk
HuZhwIR1CNrn9OvwZpgRGg2Dk2etTBidxj224uushgCTFLbzVfQ=
-----END RSA PRIVATE KEY-----"""

PUBLIC_KEY = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlytGPmlMCfwilUcIQaP9
sHLdIBDqNYFHK945RuI5EjjrjHRqjWVLCSJ1iFkKE7LPHWQLMnBsBJ30GNOYVPZz
l+ZXKFJM3n5O16QOspWHf9wIlW079Y3n16iuEtx9kNwkokld5AbNB+srb0RS4nrG
KYHhuSv5uowfh4aLWufRjSanVAsxw8XQeqEMKkXYluz+/l2Yq+mlM1lgyFnPBTwg
Ts/qpKBWSEyFVOygAnNvE6syCnxh28dh8cQP17fxxAjid1Ta/gv9EH8xpktNn4Kc
e+WqYrdL69JBxhIoDTHQOa0T+cAEgRoqgOZq1TYJlCdA3BXyM38p51NjA4eP7+Y7
oQIDAQAB
-----END PUBLIC KEY-----"""

private_key = RSA.import_key(PRIVATE_KEY)
public_key = RSA.import_key(PUBLIC_KEY)


def caesar_encrypt(plain_text, shift):
    result = ""
    for char in plain_text:
        if char.isalpha():
            start = ord("A") if char.isupper() else ord("a")
            result += chr((ord(char) - start + shift) % 26 + start)
        else:
            result += char
    return result


def caesar_decrypt(cipher_text, shift):
    return caesar_encrypt(cipher_text, -shift)


# ---------------- RSA ---------------- #

def rsa_encrypt(plain_text):
    try:
        cipher = PKCS1_OAEP.new(public_key)
        # RSA with 2048-bit key can encrypt max 190 bytes
        if len(plain_text.encode()) > 190:
            return "Error: Text too long for RSA. Maximum 190 characters."
        encrypted_bytes = cipher.encrypt(plain_text.encode())
        encoded = base64.b64encode(encrypted_bytes).decode()
        return encoded
    except Exception as e:
        return f"RSA Encryption Error: {str(e)}"


def rsa_decrypt(cipher_text):
    cipher = PKCS1_OAEP.new(private_key)
    cleaned = "".join(cipher_text.split())
    padding = (-len(cleaned)) % 4
    cleaned = cleaned + ("=" * padding)

    try:
        decoded = base64.b64decode(cleaned, validate=True)
        decrypted = cipher.decrypt(decoded).decode()
        return decrypted
    except (ValueError, TypeError) as exc:
        return f"Invalid RSA cipher text. {exc}"


# ---------------- Routes ---------------- #

@app.route("/")
def home():
    return redirect(url_for("encrypt"))


@app.route("/encrypt", methods=["GET", "POST"])
def encrypt():
    output_text = ""

    if request.method == "POST":
        plain_text = request.form.get("input_text")
        algorithm = request.form.get("algorithm")

        print("DEBUG INPUT:", plain_text, algorithm)  # 👈 DEBUG

        if not plain_text:
            output_text = "ERROR: Empty input"

        elif algorithm == "caesar":
            shift = int(request.form.get("shift", 0))
            output_text = caesar_encrypt(plain_text, shift)

        elif algorithm == "rsa":
            output_text = rsa_encrypt(plain_text)

        print("DEBUG OUTPUT:", output_text)  # 👈 DEBUG

    return render_template("encrypt.html", output=output_text)


@app.route("/decrypt", methods=["GET", "POST"])
def decrypt():
    output_text = ""

    if request.method == "POST":
        cipher_text = request.form["input_text"]
        algorithm = request.form["algorithm"]

        if algorithm == "caesar":
            shift = int(request.form["shift"])
            output_text = caesar_decrypt(cipher_text, shift)

        elif algorithm == "rsa":
            output_text = rsa_decrypt(cipher_text)

    return render_template("decrypt.html", output=output_text)


if __name__ == "__main__":

    app.run(debug=True)


