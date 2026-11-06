#!/usr/bin/env python3
"""Publish a tiny client release descriptor, or explicitly deploy the auth server."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import socket
import sys
import time
import warnings

warnings.filterwarnings(
    "ignore",
    message="You are using cryptography on a 32-bit Python.*",
    category=UserWarning,
)
import paramiko
from Crypto.Cipher import AES

from release_config import load_config


REMOTE_RELEASE_FILE = "/etc/secret-auth/client-release.json"


def capability_payload(config: dict, dll_path: Path) -> bytes:
    key = base64.b64decode(config["payload_master_key"], validate=True)
    claims = json.dumps(
        {
            "protocol": 1,
            "outer_secret": config["outer_secret"],
            "class_secret": config["class_secret"],
            "dll_sha256": hashlib.sha256(dll_path.read_bytes()).hexdigest(),
        },
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(claims)
    return nonce + ciphertext + tag


def release_descriptor(build_id: str, payload: bytes) -> bytes:
    return json.dumps(
        {
            "protocol": 1,
            "build_id": build_id,
            "published_at": int(time.time()),
            "payloads": {"alpha": base64.b64encode(payload).decode("ascii")},
        },
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def verify_artifacts(root: Path, version: str, config: dict) -> tuple[Path, list[Path], str]:
    dll_path = root / "build" / "native-ollvm" / "himitsu.dll"
    if not dll_path.is_file():
        raise RuntimeError(f"Native DLL is missing: {dll_path}")
    jars = [
        root / "build" / "libs" / f"Secret-{version}.jar",
        root / "build" / "libs" / f"Secret-{version}-obfuscated.jar",
        root / "build" / "libs" / f"Secret-{version}-encrypted-only.jar",
    ]
    dll_bytes = dll_path.read_bytes()
    for jar in jars:
        if not jar.is_file():
            raise RuntimeError(f"Final JAR is missing: {jar}")
        data = jar.read_bytes()
        if config["outer_secret"].encode() in data or config["class_secret"].encode() in data:
            raise RuntimeError(f"Plaintext release secret leaked into {jar.name}")
        import zipfile
        with zipfile.ZipFile(jar) as archive:
            if archive.read("himitsu.dll") != dll_bytes:
                raise RuntimeError(f"Packaged native DLL mismatch: {jar.name}")
    return dll_path, jars, hashlib.sha256(dll_bytes).hexdigest()


def connect(config: dict) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        config["ssh_host"],
        port=int(config["ssh_port"]),
        username=config["ssh_user"],
        password=config["ssh_password"],
        timeout=30,
        banner_timeout=30,
        auth_timeout=30,
        look_for_keys=False,
        allow_agent=False,
    )
    transport = client.get_transport()
    if transport is None:
        raise RuntimeError("SSH transport was not established")
    transport.set_keepalive(10)
    transport.sock.settimeout(30)
    return client


def run_script(client: paramiko.SSHClient, script: str, deadline_seconds: int) -> str:
    stdin, stdout, stderr = client.exec_command(
        f"timeout {deadline_seconds}s bash -s", timeout=30
    )
    stdin.write(script)
    stdin.channel.shutdown_write()
    channel = stdout.channel
    channel.settimeout(5)
    output_parts: list[str] = []
    error_parts: list[str] = []
    deadline = time.monotonic() + deadline_seconds + 10
    while True:
        while channel.recv_ready():
            chunk = channel.recv(32768).decode("utf-8", "replace")
            output_parts.append(chunk)
            print(chunk, end="", flush=True)
        while channel.recv_stderr_ready():
            chunk = channel.recv_stderr(32768).decode("utf-8", "replace")
            error_parts.append(chunk)
            print(chunk, end="", file=sys.stderr, flush=True)
        if channel.exit_status_ready():
            break
        if time.monotonic() >= deadline:
            channel.close()
            raise RuntimeError("Remote activation exceeded its deadline")
        time.sleep(0.1)
    status = channel.recv_exit_status()
    output = "".join(output_parts)
    error = "".join(error_parts)
    if status != 0:
        raise RuntimeError(f"Remote activation failed ({status}):\n{error}\n{output}")
    return output


def upload_file(client: paramiko.SSHClient, local: Path, remote: str) -> None:
    sftp = client.open_sftp()
    try:
        sftp.get_channel().settimeout(30)
        sftp.put(str(local), remote)
    finally:
        sftp.close()


def publish_client_release(
    client: paramiko.SSHClient,
    descriptor_path: Path,
    build_id: str,
    stamp: str,
) -> None:
    remote_descriptor = f"/tmp/secret-client-release-{stamp}.json"
    upload_file(client, descriptor_path, remote_descriptor)
    script = f"""
set -eu
test -d /etc/secret-auth
install -o root -g secret-auth -m 0640 '{remote_descriptor}' '{REMOTE_RELEASE_FILE}.new'
mv -f '{REMOTE_RELEASE_FILE}.new' '{REMOTE_RELEASE_FILE}'
rm -f '{remote_descriptor}'
expected='{build_id}'
healthy=0
for attempt in 1 2 3 4 5; do
  response="$(timeout 5s curl -ksSf https://127.0.0.1:8443/health || true)"
  if printf '%s' "$response" | grep -Fq '"build":"'"$expected"'"'; then
    healthy=1
    printf '%s\n' "$response"
    break
  fi
  sleep 1
done
if [ "$healthy" -ne 1 ]; then
  echo 'The running server does not support hot client releases; update the server files manually.' >&2
  exit 22
fi
"""
    run_script(client, script, 30)


def deploy(root: Path, version: str) -> None:
    print("[1/4] Verifying release artifacts...", flush=True)
    config = load_config()
    dll_path, jars, dll_hash = verify_artifacts(root, version, config)
    build_id = f"Secret-{version}"
    descriptor = release_descriptor(build_id, capability_payload(config, dll_path))
    temporary = root / "build" / "production" / "current-release.json"
    temporary.parent.mkdir(parents=True, exist_ok=True)
    temporary.write_bytes(descriptor)

    print(f"[2/4] Connecting to {config['ssh_host']}...", flush=True)
    client = connect(config)
    stamp = time.strftime("%Y%m%d%H%M%S", time.gmtime())
    try:
        print(f"[3/4] Publishing {len(descriptor)}-byte client release descriptor...", flush=True)
        publish_client_release(client, temporary, build_id, stamp)
        print("[4/4] Release published and health checked.", flush=True)
        print("client_jars=" + ",".join(jar.name for jar in jars))
        print("native_sha256=" + dll_hash)
    except (socket.timeout, TimeoutError) as exception:
        raise RuntimeError(f"Server operation timed out: {exception}") from exception
    finally:
        client.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--version", required=True)
    arguments = parser.parse_args()
    deploy(Path(arguments.root).resolve(), arguments.version)


if __name__ == "__main__":
    try:
        main()
    except Exception as exception:
        print(str(exception), file=sys.stderr)
        raise SystemExit(1)
