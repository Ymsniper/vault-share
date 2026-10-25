"""The Tailscale link to this server: where it points, and moving it when the
server's port changes.

Funnel decides what the internet can reach, so nothing here runs by itself:
the console and the command line ask first. Only rules that sent traffic to
this server's old port on this machine are changed. Funnel is never turned
on, nothing is made public, and the config is never reset.
"""
import json
import shutil
# only runs the tailscale command, with fixed arguments
import subprocess  # nosec B404
from urllib.parse import urlsplit, urlunsplit

LOCAL = {"127.0.0.1", "localhost", "::1"}


def run(args, timeout=10):
    """Run tailscale with these arguments: (exit code, output), or None when
    it is not installed or does not answer in time."""
    exe = shutil.which("tailscale")
    if exe is None:
        return None
    try:
        # a list, no shell, and the only values in it are ports this app
        # checked and paths read from Tailscale's own config
        r = subprocess.run(  # nosec B603
            [exe, *args], capture_output=True, text=True, timeout=timeout
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return r.returncode, r.stdout + r.stderr


def status(timeout=10):
    """Tailscale's serve and Funnel rules, or None when there is no Tailscale
    to ask: not installed, stopped or logged out."""
    out = run(["funnel", "status", "--json"], timeout)
    if out is None or out[0] != 0:
        return None
    try:
        data = json.loads(out[1])
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def rules(config):
    """Every rule in the config, with what moving it needs."""
    found = []
    tcp = config.get("TCP") or {}
    public = config.get("AllowFunnel") or {}
    for host, web in (config.get("Web") or {}).items():
        port = host.rpartition(":")[2]
        mode = "http" if (tcp.get(port) or {}).get("HTTP") else "https"
        for path, handler in ((web or {}).get("Handlers") or {}).items():
            proxy = (handler or {}).get("Proxy")
            if isinstance(proxy, str):
                found.append({"host": host, "port": port, "mode": mode, "path": path,
                              "proxy": proxy, "public": bool(public.get(host))})
    return found


def local_port(proxy):
    """The port a rule sends traffic to on this machine, or None."""
    try:
        target = urlsplit(proxy)
        return target.port if target.hostname in LOCAL else None
    except ValueError:
        return None


def rules_for(config, port):
    """The rules that send traffic to this machine at port."""
    return [r for r in rules(config or {}) if local_port(r["proxy"]) == port]


def url_of(rule):
    host = rule["host"].rpartition(":")[0]
    default = "443" if rule["mode"] == "https" else "80"
    port = "" if rule["port"] == default else f":{rule['port']}"
    path = "" if rule["path"] == "/" else rule["path"]
    return f"{rule['mode']}://{host}{port}{path}"


def command(rule, new_port, https):
    """The tailscale arguments that point this rule at new_port, keeping it
    public or tailnet-only as it was."""
    old = urlsplit(rule["proxy"])
    target = urlunsplit(("https+insecure" if https else "http", f"127.0.0.1:{int(new_port)}",
                         old.path, old.query, ""))
    return ["funnel" if rule["public"] else "serve", "--bg", "--yes",
            f"--{rule['mode']}={rule['port']}", f"--set-path={rule['path']}", target]


def by_hand(found, new_port, https):
    return "; ".join("tailscale " + " ".join(command(r, new_port, https)) for r in found)


def move(old_port, new_port, https):
    """Point the rules that sent traffic to old_port at new_port, then check
    that Tailscale took the change. Returns what happened, in a sentence."""
    moving = rules_for(status(), old_port)
    if not moving:
        return f"No Tailscale link pointed at port {old_port}, so nothing was changed."
    for rule in moving:
        out = run(command(rule, new_port, https))
        if out is None or out[0] != 0:
            return ("Tailscale did not take the change. Run this yourself: "
                    + by_hand(moving, new_port, https))
    if rules_for(status(), old_port):
        return ("Tailscale still points at the old port. Run this yourself: "
                + by_hand(moving, new_port, https))
    return f"Moved {', '.join(url_of(r) for r in moving)} to port {new_port}."


def describe(config, port):
    """Where the Tailscale link points, for the console: (text, all well)."""
    if config is None:
        return "no Tailscale link", True
    found = rules(config)
    here = [r for r in found if local_port(r["proxy"]) == port]
    if here:
        return ", ".join(url_of(r) + (" (public)" if r["public"] else "")
                         for r in here) + ", to this server", True
    elsewhere = [r for r in found if local_port(r["proxy"]) is not None]
    if elsewhere:
        r = elsewhere[0]
        return (f"{url_of(r)} points at port {local_port(r['proxy'])},"
                f" not this server (port {port})"), False
    return "no Tailscale link", True
