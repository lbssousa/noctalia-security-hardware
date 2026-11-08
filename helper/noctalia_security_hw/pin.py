"""PINs: from the plugin's file to the helper's memory, and to ssh-keygen as its askpass."""

import asyncio
import os
import socket

ASKPASS_ENV = "NOCTALIA_SECURITY_HW_ASKPASS_SOCKET"


class PinFileError(Exception):
    pass


def take_pin(path, pins_dir):
    """Reads the PIN the plugin wrote to a 0600 file in <pins_dir>, and removes the file at
    once. Only files right inside that directory, never through a symbolic link."""
    if not path:
        return ""
    if os.path.dirname(os.path.abspath(path)) != os.path.abspath(pins_dir):
        raise PinFileError("PIN file outside %s" % pins_dir)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as e:
        raise PinFileError(str(e)) from e
    try:
        with os.fdopen(fd, "rb") as f:
            data = f.read(256)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    return data.decode("utf-8", "replace").rstrip("\r\n")


async def serve_pin(path, pin):
    """Answers the first PIN prompt of our own askpass over a socket only we can reach."""
    given = False

    async def answer(reader, writer):
        nonlocal given
        prompt = (await reader.readline()).decode("utf-8", "replace")
        reply = ""
        if pin and not given and "PIN" in prompt:
            reply = pin
            given = True
        writer.write((reply + "\n").encode())
        await writer.drain()
        writer.close()

    old = os.umask(0o077)
    try:
        return await asyncio.start_unix_server(answer, path=path)
    finally:
        os.umask(old)


def askpass(prompt):
    """SSH_ASKPASS mode: prints the PIN the running helper hands over, or fails."""
    path = os.environ.get(ASKPASS_ENV, "")
    if not path:
        return 1
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.connect(path)
            s.sendall((prompt.replace("\n", " ") + "\n").encode())
            reply = b""
            while not reply.endswith(b"\n"):
                chunk = s.recv(1024)
                if not chunk:
                    break
                reply += chunk
    except OSError:
        return 1
    answer = reply.decode("utf-8", "replace").rstrip("\n")
    if not answer:
        return 1
    print(answer)
    return 0
