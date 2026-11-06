#!/usr/bin/env python3
"""Manage the local DPAPI-protected production release configuration."""

import argparse
import base64
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys


class DataBlob(ctypes.Structure):
    _fields_ = [("size", wintypes.DWORD), ("data", ctypes.POINTER(ctypes.c_ubyte))]


CRYPTPROTECT_UI_FORBIDDEN = 0x1
ENTROPY = b"Himitsu-Production-Release-Config-v1"
CONFIG_PATH = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "Himitsu" / "release-config.bin"



SSH_HOST = os.environ.get("HIMITSU_DEPLOY_SSH_HOST", "your-server.example.com")
SSH_PORT = int(os.environ.get("HIMITSU_DEPLOY_SSH_PORT", "2222"))
SSH_USER = os.environ.get("HIMITSU_DEPLOY_SSH_USER", "root")


def make_blob(value: bytes):
    buffer = ctypes.create_string_buffer(value)
    blob = DataBlob(len(value), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))
    return blob, buffer


def protect(value: bytes) -> bytes:
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    input_blob, input_buffer = make_blob(value)
    entropy_blob, entropy_buffer = make_blob(ENTROPY)
    output_blob = DataBlob()
    if not crypt32.CryptProtectData(
        ctypes.byref(input_blob),
        "Himitsu release config",
        ctypes.byref(entropy_blob),
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(output_blob),
    ):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(output_blob.data, output_blob.size)
    finally:
        kernel32.LocalFree(output_blob.data)
        del input_buffer, entropy_buffer


def unprotect(value: bytes) -> bytes:
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    input_blob, input_buffer = make_blob(value)
    entropy_blob, entropy_buffer = make_blob(ENTROPY)
    output_blob = DataBlob()
    if not crypt32.CryptUnprotectData(
        ctypes.byref(input_blob),
        None,
        ctypes.byref(entropy_blob),
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(output_blob),
    ):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(output_blob.data, output_blob.size)
    finally:
        kernel32.LocalFree(output_blob.data)
        del input_buffer, entropy_buffer


def restrict_acl(path: Path) -> None:
    username = os.environ.get("USERNAME")
    if not username:
        return
    subprocess.run(
        [
            "icacls",
            str(path),
            "/inheritance:r",
            "/grant:r",
            f"{username}:(R,W)",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def save_config(config: dict) -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(config, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    temporary = CONFIG_PATH.with_suffix(".tmp")
    temporary.write_bytes(protect(encoded))
    os.replace(temporary, CONFIG_PATH)
    restrict_acl(CONFIG_PATH)


def load_config() -> dict:
    if not CONFIG_PATH.is_file():
        raise RuntimeError(
            "Production release config is missing. Run: "
            "python tools/release_config.py init"
        )
    config = json.loads(unprotect(CONFIG_PATH.read_bytes()).decode("utf-8"))
    required = {
        "ssh_host",
        "ssh_port",
        "ssh_user",
        "ssh_password",
        "payload_master_key",
        "outer_secret",
        "class_secret",
    }
    missing = sorted(required.difference(config))
    if missing:
        raise RuntimeError("Release config is missing: " + ", ".join(missing))
    if len(base64.b64decode(config["payload_master_key"], validate=True)) != 32:
        raise RuntimeError("Release payload master key is invalid")
    if len(config["outer_secret"]) < 32 or len(config["class_secret"]) < 32:
        raise RuntimeError("Release payload secrets are invalid")
    return config


def initialize(force: bool) -> None:
    if CONFIG_PATH.exists() and not force:
        raise RuntimeError(f"Release config already exists: {CONFIG_PATH}")
    password = os.environ.get("HIMITSU_DEPLOY_SSH_PASSWORD")
    if not password:
        import getpass
        password = getpass.getpass("Production SSH password: ")
    if not password:
        raise RuntimeError("Production SSH password cannot be empty")
    save_config({
        "ssh_host": SSH_HOST,
        "ssh_port": SSH_PORT,
        "ssh_user": SSH_USER,
        "ssh_password": password,
        "payload_master_key": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
        "outer_secret": base64.urlsafe_b64encode(secrets.token_bytes(48)).decode("ascii"),
        "class_secret": base64.urlsafe_b64encode(secrets.token_bytes(48)).decode("ascii"),
    })
    print(f"Created DPAPI-protected release config: {CONFIG_PATH}")


def import_production(force: bool) -> None:
    if CONFIG_PATH.exists() and not force:
        raise RuntimeError(f"Release config already exists: {CONFIG_PATH}")
    password = os.environ.get("HIMITSU_DEPLOY_SSH_PASSWORD")
    if not password:
        import getpass
        password = getpass.getpass("Production SSH password: ")
    if not password:
        raise RuntimeError("Production SSH password cannot be empty")

    import paramiko
    from Crypto.Cipher import AES

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        SSH_HOST,
        port=SSH_PORT,
        username=SSH_USER,
        password=password,
        timeout=30,
        banner_timeout=30,
        auth_timeout=30,
        look_for_keys=False,
        allow_agent=False,
    )
    try:
        _, stdout, stderr = client.exec_command(
            "sed -n 's/^SECRET_AUTH_PAYLOAD_MASTER_KEY=//p' "
            "/etc/secret-auth/secret-auth.env"
        )
        master_key = stdout.read().decode("ascii", "strict").strip()
        error = stderr.read().decode("utf-8", "replace").strip()
        if stdout.channel.recv_exit_status() != 0 or not master_key:
            raise RuntimeError(error or "Production payload master key is unavailable")
        sftp = client.open_sftp()
        try:
            with sftp.open("/var/lib/secret-auth/data/payloads/tier_alpha.dat", "rb") as source:
                encrypted = source.read()
        finally:
            sftp.close()
    finally:
        client.close()

    key = base64.b64decode(master_key, validate=True)
    if len(key) != 32 or len(encrypted) < 28:
        raise RuntimeError("Production capability payload is invalid")
    plaintext = AES.new(key, AES.MODE_GCM, nonce=encrypted[:12]).decrypt_and_verify(
        encrypted[12:-16], encrypted[-16:]
    )
    claims = json.loads(plaintext.decode("ascii"))
    save_config({
        "ssh_host": SSH_HOST,
        "ssh_port": SSH_PORT,
        "ssh_user": SSH_USER,
        "ssh_password": password,
        "payload_master_key": master_key,
        "outer_secret": claims["outer_secret"],
        "class_secret": claims["class_secret"],
    })
    print(f"Imported production release config: {CONFIG_PATH}")


def main() -> None:
    parser = argparse.ArgumentParser()
    subcommands = parser.add_subparsers(dest="command", required=True)
    init_parser = subcommands.add_parser("init")
    init_parser.add_argument("--force", action="store_true")
    import_parser = subcommands.add_parser("import-production")
    import_parser.add_argument("--force", action="store_true")
    subcommands.add_parser("build-json")
    subcommands.add_parser("path")
    arguments = parser.parse_args()

    if arguments.command == "init":
        initialize(arguments.force)
    elif arguments.command == "import-production":
        import_production(arguments.force)
    elif arguments.command == "build-json":
        config = load_config()
        print(json.dumps({
            "outer_secret": config["outer_secret"],
            "class_secret": config["class_secret"],
        }, separators=(",", ":")))
    elif arguments.command == "path":
        print(CONFIG_PATH)


if __name__ == "__main__":
    try:
        main()
    except Exception as exception:
        print(str(exception), file=sys.stderr)
        raise SystemExit(1)
