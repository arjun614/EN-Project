"""
LAN File Sharing - Python TCP sockets + Tkinter GUI
Run the same script on both computers. Each one can send and receive.

Protocol (application layer over TCP):
  1. Sender -> Receiver : 4-byte big-endian length N of the JSON header
  2. Sender -> Receiver : JSON header {"name": str, "size": int, "sha256": str}
  3. Sender -> Receiver : raw file bytes (exactly `size` bytes)
  4. Receiver -> Sender : b"OK" if SHA-256 matches, else b"ER"
"""

import hashlib
import json
import os
import queue
import socket
import struct
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

CHUNK_SIZE = 64 * 1024
LEN_FMT = struct.Struct("!I")
DEFAULT_PORT = 5001


# ----------------------------------------------------------------- helpers
def get_local_ip():
    """Find this machine's LAN IP (no packets are actually sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def recv_exact(conn, n):
    """TCP is a stream, so keep reading until exactly n bytes arrive."""
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed before all data arrived")
        buf.extend(chunk)
    return bytes(buf)


def sha256_of_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            block = f.read(CHUNK_SIZE)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def unique_path(folder, name):
    """Avoid overwriting: report.pdf -> report (1).pdf"""
    base, ext = os.path.splitext(name)
    path = os.path.join(folder, name)
    i = 1
    while os.path.exists(path):
        path = os.path.join(folder, f"{base} ({i}){ext}")
        i += 1
    return path


def human(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024


# ------------------------------------------------------------ server logic
class FileServer:
    def __init__(self, port, save_dir, ui_queue):
        self.port, self.save_dir, self.q = port, save_dir, ui_queue
        self.stop_event = threading.Event()
        self.sock = None

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("0.0.0.0", self.port))  # listen on all interfaces
        self.sock.listen(5)
        self.sock.settimeout(1.0)  # so the loop can notice stop_event
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def stop(self):
        self.stop_event.set()
        if self.sock:
            self.sock.close()

    def _accept_loop(self):
        while not self.stop_event.is_set():
            try:
                conn, addr = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn, addr), daemon=True).start()

    def _handle(self, conn, addr):
        dest = None
        try:
            conn.settimeout(30)
            hlen = LEN_FMT.unpack(recv_exact(conn, LEN_FMT.size))[0]
            header = json.loads(recv_exact(conn, hlen).decode("utf-8"))
            name = os.path.basename(header["name"])  # block path traversal
            size, expected = int(header["size"]), header["sha256"]
            dest = unique_path(self.save_dir, name)
            self.q.put(("log", f"[RX] Incoming '{name}' ({human(size)}) from {addr[0]}"))

            h, got = hashlib.sha256(), 0
            with open(dest, "wb") as f:
                while got < size:
                    data = conn.recv(min(CHUNK_SIZE, size - got))
                    if not data:
                        raise ConnectionError("Sender disconnected mid-transfer")
                    f.write(data)
                    h.update(data)
                    got += len(data)
                    self.q.put(("recv_prog", got * 100 / size if size else 100))

            if h.hexdigest() == expected:
                conn.sendall(b"OK")
                self.q.put(("log", f"[RX] Saved to {dest} (checksum OK)"))
            else:
                conn.sendall(b"ER")
                os.remove(dest)
                self.q.put(("log", "[RX] Checksum mismatch - file discarded"))
        except Exception as e:
            self.q.put(("log", f"[RX] Error: {e}"))
            if dest and os.path.exists(dest):
                os.remove(dest)
        finally:
            conn.close()


# ------------------------------------------------------------ client logic
def send_file(host, port, path, ui_queue):
    try:
        size = os.path.getsize(path)
        name = os.path.basename(path)
        ui_queue.put(("log", f"[TX] Computing checksum for '{name}'..."))
        header = json.dumps(
            {"name": name, "size": size, "sha256": sha256_of_file(path)}
        ).encode("utf-8")

        with socket.create_connection((host, port), timeout=5) as s:
            s.settimeout(30)
            ui_queue.put(("log", f"[TX] Connected to {host}:{port}, sending {human(size)}"))
            s.sendall(LEN_FMT.pack(len(header)) + header)

            sent = 0
            with open(path, "rb") as f:
                while True:
                    block = f.read(CHUNK_SIZE)
                    if not block:
                        break
                    s.sendall(block)
                    sent += len(block)
                    ui_queue.put(("send_prog", sent * 100 / size if size else 100))

            ack = recv_exact(s, 2)
            if ack == b"OK":
                ui_queue.put(("log", f"[TX] '{name}' delivered and verified"))
            else:
                ui_queue.put(("log", f"[TX] Receiver reported a checksum error"))
    except (ConnectionRefusedError, socket.timeout):
        ui_queue.put(("log", "[TX] Could not connect. Check IP, port, receiver status and firewall."))
    except Exception as e:
        ui_queue.put(("log", f"[TX] Error: {e}"))
    finally:
        ui_queue.put(("send_done", None))


# --------------------------------------------------------------------- GUI
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("LAN File Share (TCP)")
        self.geometry("640x560")
        self.minsize(560, 500)
        self.q = queue.Queue()
        self.server = None
        self.file_path = tk.StringVar()
        self.save_dir = tk.StringVar(value=os.path.join(os.path.expanduser("~"), "Downloads"))
        self.recv_port = tk.StringVar(value=str(DEFAULT_PORT))
        self.peer_ip = tk.StringVar()
        self.peer_port = tk.StringVar(value=str(DEFAULT_PORT))
        self._build()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(100, self._poll_queue)

    def _build(self):
        pad = {"padx": 10, "pady": 6}
        top = ttk.Label(self, text=f"This computer's IP:  {get_local_ip()}",
                        font=("Segoe UI", 12, "bold"))
        top.pack(anchor="w", **pad)

        # Receive panel
        rx = ttk.LabelFrame(self, text="Receive files (server)")
        rx.pack(fill="x", **pad)
        ttk.Label(rx, text="Port").grid(row=0, column=0, sticky="w", padx=8, pady=4)
        ttk.Entry(rx, textvariable=self.recv_port, width=8).grid(row=0, column=1, sticky="w")
        ttk.Label(rx, text="Save to").grid(row=1, column=0, sticky="w", padx=8, pady=4)
        ttk.Entry(rx, textvariable=self.save_dir).grid(row=1, column=1, sticky="ew", padx=4)
        ttk.Button(rx, text="Browse", command=self._pick_dir).grid(row=1, column=2, padx=8)
        self.listen_btn = ttk.Button(rx, text="Start listening", command=self._toggle_server)
        self.listen_btn.grid(row=2, column=0, columnspan=3, sticky="ew", padx=8, pady=4)
        self.recv_bar = ttk.Progressbar(rx, maximum=100)
        self.recv_bar.grid(row=3, column=0, columnspan=3, sticky="ew", padx=8, pady=(0, 8))
        rx.columnconfigure(1, weight=1)

        # Send panel
        tx = ttk.LabelFrame(self, text="Send a file (client)")
        tx.pack(fill="x", **pad)
        ttk.Label(tx, text="Receiver IP").grid(row=0, column=0, sticky="w", padx=8, pady=4)
        ttk.Entry(tx, textvariable=self.peer_ip, width=18).grid(row=0, column=1, sticky="w")
        ttk.Label(tx, text="Port").grid(row=0, column=2, padx=(12, 4))
        ttk.Entry(tx, textvariable=self.peer_port, width=8).grid(row=0, column=3, sticky="w")
        ttk.Label(tx, text="File").grid(row=1, column=0, sticky="w", padx=8, pady=4)
        ttk.Entry(tx, textvariable=self.file_path).grid(row=1, column=1, columnspan=3, sticky="ew", padx=4)
        ttk.Button(tx, text="Browse", command=self._pick_file).grid(row=1, column=4, padx=8)
        self.send_btn = ttk.Button(tx, text="Send", command=self._send)
        self.send_btn.grid(row=2, column=0, columnspan=5, sticky="ew", padx=8, pady=4)
        self.send_bar = ttk.Progressbar(tx, maximum=100)
        self.send_bar.grid(row=3, column=0, columnspan=5, sticky="ew", padx=8, pady=(0, 8))
        tx.columnconfigure(3, weight=1)

        # Log
        lg = ttk.LabelFrame(self, text="Activity log")
        lg.pack(fill="both", expand=True, **pad)
        self.log = tk.Text(lg, height=8, state="disabled", wrap="word")
        self.log.pack(fill="both", expand=True, padx=6, pady=6)

    # --- actions
    def _pick_dir(self):
        d = filedialog.askdirectory()
        if d:
            self.save_dir.set(d)

    def _pick_file(self):
        f = filedialog.askopenfilename()
        if f:
            self.file_path.set(f)

    def _toggle_server(self):
        if self.server:
            self.server.stop()
            self.server = None
            self.listen_btn.config(text="Start listening")
            self._log("[RX] Server stopped")
            return
        try:
            port = int(self.recv_port.get())
            os.makedirs(self.save_dir.get(), exist_ok=True)
            self.server = FileServer(port, self.save_dir.get(), self.q)
            self.server.start()
        except (ValueError, OSError) as e:
            self.server = None
            messagebox.showerror("Cannot start server", str(e))
            return
        self.listen_btn.config(text="Stop listening")
        self._log(f"[RX] Listening on port {port}")

    def _send(self):
        host, path = self.peer_ip.get().strip(), self.file_path.get()
        try:
            port = int(self.peer_port.get())
        except ValueError:
            return messagebox.showerror("Invalid port", "Port must be a number")
        if not host or not os.path.isfile(path):
            return messagebox.showerror("Missing input", "Enter receiver IP and choose a valid file")
        self.send_btn.config(state="disabled")
        self.send_bar["value"] = 0
        threading.Thread(target=send_file, args=(host, port, path, self.q), daemon=True).start()

    # --- UI plumbing (worker threads never touch widgets directly)
    def _log(self, text):
        self.log.config(state="normal")
        self.log.insert("end", text + "\n")
        self.log.see("end")
        self.log.config(state="disabled")

    def _poll_queue(self):
        try:
            while True:
                kind, val = self.q.get_nowait()
                if kind == "log":
                    self._log(val)
                elif kind == "send_prog":
                    self.send_bar["value"] = val
                elif kind == "recv_prog":
                    self.recv_bar["value"] = val
                elif kind == "send_done":
                    self.send_btn.config(state="normal")
        except queue.Empty:
            pass
        self.after(100, self._poll_queue)

    def _on_close(self):
        if self.server:
            self.server.stop()
        self.destroy()


if __name__ == "__main__":
    App().mainloop()
