#!/usr/bin/env python3
"""Forward one TCP connection, count what crosses it, and emulate a link.

The prover and the verifier of a dispute talk over one TCP connection. This
script sits between them: it accepts a connection on localhost:PORT,
connects to localhost:TARGET, and forwards the bytes both ways. When both
sides have closed, it prints the bytes sent each way and the number of
flights, the runs of bytes in one direction: a protocol with f flights
waits about f times the one-way latency.

With --latency-ms and --rate-mbit, it delays and paces each direction as a
link with that one-way latency and that bandwidth would, for instance a
phone's mobile link, where the uplink is the slower direction.

  link.py PORT TARGET [--latency-ms L] [--rate-mbit TO FROM]

TO is the bandwidth toward TARGET, FROM the bandwidth from it, in Mbit/s.
Diet Mac'n'Cheese's verifier listens and its prover connects, so its
prover connects to PORT with the verifier at TARGET; emp-zk's prover
(party 1) listens, so its verifier connects to PORT with the prover at
TARGET.
"""

import argparse
import collections
import socket
import sys
import threading
import time


def relay(port, target, latency, rates):
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", port))
    server.listen(1)
    near, _ = server.accept()
    far = socket.create_connection(("127.0.0.1", target))
    for s in (near, far):
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    lock = threading.Lock()
    flights = {"last": None, "count": 0}
    counts = {}

    def pump(src, dst, name, rate):
        queue = collections.deque()
        ready = threading.Condition()
        closed = []

        def deliver():
            while True:
                with ready:
                    while not queue and not closed:
                        ready.wait()
                    if not queue:
                        break
                    due, data = queue.popleft()
                wait = due - time.monotonic()
                if wait > 0:
                    time.sleep(wait)
                dst.sendall(data)
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

        writer = threading.Thread(target=deliver)
        writer.start()
        total, busy = 0, 0.0
        while data := src.recv(1 << 16):
            now = time.monotonic()
            with lock:
                if flights["last"] != name:
                    flights["last"] = name
                    flights["count"] += 1
            busy = max(now, busy) + (len(data) * 8 / (rate * 1e6) if rate else 0.0)
            with ready:
                queue.append((busy + latency, data))
                ready.notify()
            total += len(data)
        with ready:
            closed.append(True)
            ready.notify()
        writer.join()
        counts[name] = total

    threads = [
        threading.Thread(target=pump, args=(near, far, "to", rates[0])),
        threading.Thread(target=pump, args=(far, near, "from", rates[1])),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    print(
        f"toward {target}: {counts['to']} B, from {target}: {counts['from']} B,",
        f"flights: {flights['count']}",
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("port", type=int)
    parser.add_argument("target", type=int)
    parser.add_argument("--latency-ms", type=float, default=0.0)
    parser.add_argument(
        "--rate-mbit", type=float, nargs=2, default=(0.0, 0.0), metavar=("TO", "FROM")
    )
    args = parser.parse_args()
    relay(args.port, args.target, args.latency_ms / 1000, args.rate_mbit)


if __name__ == "__main__":
    sys.exit(main())
