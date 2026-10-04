
import hashlib
import pickle
import subprocess

import yaml
from flask import Flask, request

app = Flask(__name__)

# Hard-coded credentials -> secrets + SAST findings
DB_PASSWORD = "Santile@tes12!"
api_key = "x9Qm4Rkhdfgebsgfdbxv56c1Fd0Gy7"


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # Command injection: user input passed to a shell
    return subprocess.check_output("ping -c 1 " + host, shell=True)


@app.route("/load", methods=["POST"])
def load():
    # Insecure deserialisation
    return str(pickle.loads(request.data))


@app.route("/config", methods=["POST"])
def config():
    # Unsafe YAML load
    return str(yaml.load(request.data, Loader=yaml.Loader))


def hash_password(pw):
    # Weak hash for passwords
    return hashlib.md5(pw.encode()).hexdigest()


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
