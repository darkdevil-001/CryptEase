from flask import Flask, render_template, request, redirect, url_for
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


app = Flask(__name__)

# Generate RSA keys on startup for demo use.
_key = RSA.generate(64)
public_key = _key.publickey()
private_key = _key


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
