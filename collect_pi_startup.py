#!/usr/bin/python3.11
"""Collect startup evidence as data. This does not admit or run the application."""
import sys

if __name__ == "__main__" and not (
    sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
):
    sys.exit("Run with /usr/bin/python3.11 -I -B -S collect_pi_startup.py")

import os

if __name__ == "__main__" and set(os.environ) - {"PATH", "LC_ALL", "LC_CTYPE"}:
    sys.exit("Use env -i PATH=/usr/bin:/bin LC_ALL=C before the isolated Python command.")

from contextlib import contextmanager
import hashlib
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import re
import selectors
import stat
import subprocess
import sysconfig
import tarfile
import tempfile
import time
import _imp
from importlib import _bootstrap_external

TEST_ROOT = Path("/home/admin/satgs-pi-test")
APP = TEST_ROOT / "satgs-app-manager"
FAILED = TEST_ROOT / "installed-check-run-eh1zctbe"
FAILED_SHA = "b93f471f3937fff576994d94ea6e5bfa7735b82bb5950871081c970f38764c91"
SUPPORT = Path("/home/admin/Downloads/check-support-offline-20261014-v2")
HOOKS = ("sitecustomize", "usercustomize")
FILE_LIMIT = 2 * 1024 * 1024
TOTAL_LIMIT = 16 * 1024 * 1024
ENTRY_LIMIT = 30000
RECORD_LIMIT = 512


def identity(value):
    return {"mode": oct(stat.S_IMODE(value.st_mode)), "uid": value.st_uid,
            "gid": value.st_gid, "dev": value.st_dev, "ino": value.st_ino,
            "size": value.st_size, "mtime_ns": value.st_mtime_ns,
            "ctime_ns": value.st_ctime_ns, "type": stat.S_IFMT(value.st_mode)}


def ordinary_parents(path):
    for parent in reversed(path.parents):
        if not stat.S_ISDIR(parent.lstat().st_mode):
            raise ValueError("nonordinary ancestor: " + str(parent))


@contextmanager
def open_directory(path):
    path = Path(path)
    descriptors = []
    try:
        current = Path("/")
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        descriptors.append((current, fd, identity(os.fstat(fd))))
        for part in path.parts[1:]:
            fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            current = current / part
            descriptors.append((current, fd, identity(os.fstat(fd))))
        yield fd
        for parent, descriptor, before in descriptors:
            now = identity(parent.lstat())
            keys = tuple(before) if parent == path else ("dev", "ino", "type", "mode", "uid", "gid")
            if any(now[key] != before[key] for key in keys):
                raise ValueError("directory replaced during inventory")
    finally:
        for _, descriptor, _ in reversed(descriptors):
            os.close(descriptor)


def read_regular(path, limit=FILE_LIMIT):
    """No link traversal or nonregular open; compare identities around the read."""
    path = Path(path)
    if not path.is_absolute():
        raise ValueError("absolute path required")
    directories, fd = [], None
    try:
        directory = os.open("/", os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        directories.append((Path("/"), directory, identity(os.fstat(directory))))
        current = Path("/")
        for part in path.parts[1:-1]:
            directory = os.open(part, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                dir_fd=directory)
            current = current / part
            directories.append((current, directory, identity(os.fstat(directory))))
        before = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("not an ordinary regular file")
        if before.st_size > limit:
            raise ValueError("file byte limit exceeded")
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=directory)
        if identity(os.fstat(fd)) != identity(before):
            raise ValueError("file changed before read")
        blocks, length = [], 0
        while True:
            block = os.read(fd, min(65536, limit + 1 - length))
            if not block:
                break
            blocks.append(block)
            length += len(block)
            if length > limit:
                raise ValueError("file grew beyond byte limit")
        ordinary_parents(path)
        if identity(os.fstat(fd)) != identity(before) or identity(path.lstat()) != identity(before):
            raise ValueError("file changed during read")
        for parent, descriptor, previous in directories:
            now = identity(parent.lstat())
            if any(now[k] != previous[k] for k in ("dev", "ino", "type", "mode", "uid", "gid")):
                raise ValueError("ancestor replaced during read")
        return b"".join(blocks), identity(before)
    finally:
        if fd is not None:
            os.close(fd)
        for _, descriptor, _ in reversed(directories):
            os.close(descriptor)


def hook_name(name):
    return any(name == hook or name.startswith(hook + ".") for hook in HOOKS)


class Collector:
    def __init__(self, output, link_roots=()):
        self.output = Path(output)
        self.link_roots = tuple(Path(p) for p in link_roots)
        self.records, self.problems, self.selections = [], [], []
        self.ancestors = {}
        self.total = 0
        self.seen = {}

    def capture(self, path, role, follow_hook=False):
        path = Path(os.path.abspath(path))
        key = str(path)
        if key in self.seen:
            return self.seen[key]
        if len(self.records) >= RECORD_LIMIT:
            raise ValueError("evidence record limit exceeded")
        record = {"path": key, "role": role}
        self.records.append(record)
        self.seen[key] = record
        observed = False
        try:
            ordinary_parents(path)
            for parent in reversed(path.parents):
                metadata = identity(parent.lstat())
                previous = self.ancestors.setdefault(str(parent), metadata)
                if any(previous[k] != metadata[k] for k in ("dev", "ino", "type", "mode", "uid", "gid")):
                    raise ValueError("ancestor identity or permissions changed")
            metadata = path.lstat()
            observed = True
            record["identity"] = identity(metadata)
            if stat.S_ISLNK(metadata.st_mode):
                record["status"] = "symlink_observed"
                record["link"] = os.readlink(path)
                if identity(path.lstat()) != identity(metadata):
                    raise ValueError("link changed during observation")
                if follow_hook:
                    target = Path(os.path.abspath(path.parent / record["link"]))
                    allowed = any(target.is_relative_to(root) for root in self.link_roots)
                    if not allowed or target.name != path.name or path.suffix != ".py":
                        raise ValueError("hook source link target outside explicit scope")
                    target_record = self.capture(target, "verified hook source link target")
                    if target_record["status"] != "captured":
                        raise ValueError("hook source link target not an ordinary captured file")
                    if identity(path.lstat()) != identity(metadata):
                        raise ValueError("source link changed during target read")
                    record["verified_target"] = str(target)
                    record["lexical_cache_path"] = importlib.util.cache_from_source(str(path))
                    self.caches(target)
            elif stat.S_ISDIR(metadata.st_mode):
                record["status"] = "directory_observed"
            else:
                data, read_identity = read_regular(path)
                if read_identity != identity(metadata):
                    raise ValueError("file replaced after observation")
                record["identity"] = read_identity
                if self.total + len(data) > TOTAL_LIMIT:
                    raise ValueError("aggregate byte limit exceeded")
                blob = "data-%04d.bin" % len(self.records)
                with (self.output / blob).open("xb") as stream:
                    stream.write(data)
                self.total += len(data)
                record.update(status="captured", blob=blob, sha256=hashlib.sha256(data).hexdigest())
                if path.suffix == ".py":
                    record["runtime_source_hash_hex"] = importlib.util.source_hash(data).hex()
                    record["lexical_cache_path"] = importlib.util.cache_from_source(str(path))
                if path.suffix == ".pyc":
                    record["cache_header_hex"] = data[:16].hex()
                    record["cache_interpretation"] = "data only; not unmarshalled or executed"
        except FileNotFoundError:
            if observed:
                record.update(status="unresolved", error="entry disappeared after initial observation")
                self.problems.append({"path": key, "error": record["error"]})
            else:
                record["status"] = "absent"
        except (OSError, ValueError) as error:
            record.update(status="unresolved", error=type(error).__name__ + ": " + str(error))
            self.problems.append({"path": key, "error": record["error"]})
        return record

    def interpreter(self, path, roots):
        path = Path(os.path.abspath(path))
        result = {"requested_path": str(path), "links": []}
        try:
            for _ in range(8):
                ordinary_parents(path)
                value = path.lstat()
                if not stat.S_ISLNK(value.st_mode):
                    data, metadata = read_regular(path, 64 * 1024 * 1024)
                    if metadata != identity(value):
                        raise ValueError("interpreter replaced after observation")
                    result.update(path=str(path), identity=metadata, sha256=hashlib.sha256(data).hexdigest())
                    break
                target = os.readlink(path)
                result["links"].append({"path": str(path), "target": target, "identity": identity(value)})
                path = Path(os.path.abspath(path.parent / target))
                if path.name not in ("python", "python3", "python3.11") or not any(path.parent == root for root in roots):
                    raise ValueError("interpreter link target outside explicit scope")
            else:
                raise ValueError("interpreter link depth exceeded")
            for link in result["links"]:
                if identity(Path(link["path"]).lstat()) != link["identity"] or os.readlink(link["path"]) != link["target"]:
                    raise ValueError("interpreter link changed")
        except (OSError, ValueError) as error:
            result["error"] = type(error).__name__ + ": " + str(error)
            self.problems.append({"path": str(path), "error": result["error"]})
        return result

    def caches(self, source):
        source = Path(source)
        self.capture(source.with_suffix(".pyc"), "legacy cache candidate")
        cache = source.parent / "__pycache__"
        directory_record = self.capture(cache, "tagged cache directory")
        if directory_record["status"] != "directory_observed":
            return
        try:
            ordinary_parents(cache)
            if not stat.S_ISDIR(cache.lstat().st_mode):
                raise ValueError("observed cache directory changed type")
            with open_directory(cache) as fd, os.scandir(fd) as entries:
                for index, entry in enumerate(entries):
                    if index >= ENTRY_LIMIT:
                        raise ValueError("cache entry limit exceeded")
                    if entry.name.startswith(source.stem + ".") and entry.name.endswith(".pyc"):
                        record = self.capture(cache / entry.name, "tagged cache candidate")
                        if record["status"] == "absent":
                            raise ValueError("listed cache disappeared during collection")
        except FileNotFoundError:
            raise ValueError("observed cache directory disappeared")

    def candidates(self, root):
        root = Path(root)
        root_record = self.capture(root, "conditional import-path directory")
        if root_record["status"] != "directory_observed":
            return
        for hook in HOOKS:
            package = root / hook
            self.capture(package, "hook package candidate")
            for parent, stem in ((root, hook), (package, "__init__")):
                for suffix in importlib.machinery.EXTENSION_SUFFIXES + [".py", ".pyc"]:
                    self.capture(parent / (stem + suffix), "direct hook candidate", follow_hook=True)
                self.caches(parent / (stem + ".py"))
            unsafe = any(r["status"] == "unresolved" or
                         (r["status"] == "symlink_observed" and "verified_target" not in r)
                         for r in self.records if Path(r["path"]).parent in (root, package))
            if unsafe:
                self.selections.append({"root": str(root), "hook": hook, "status": "unresolved"})
                continue
            # FileFinder identifies a candidate. No loader get_code/exec_module is called.
            finder = importlib.machinery.FileFinder(str(root), *_bootstrap_external._get_supported_file_loaders())
            before = identity(root.lstat())
            spec = finder.find_spec(hook)
            if identity(root.lstat()) != before:
                raise ValueError("conditional import directory changed during discovery")
            self.selections.append({"root": str(root), "hook": hook,
                                    "origin": None if spec is None else spec.origin,
                                    "loader": None if spec is None or spec.loader is None else type(spec.loader).__name__,
                                    "namespace": bool(spec is not None and spec.loader is None),
                                    "status": "conditional discovery only, no code loaded"})

    def inventory(self, root, app_site=False):
        """Bounded names only; unrelated module contents are never collected."""
        root = Path(root)
        root_record = self.capture(root, "startup inventory directory")
        if root_record["status"] != "directory_observed":
            return
        pending, count = [(root, 0)], 0
        while pending:
            directory, depth = pending.pop()
            try:
                ordinary_parents(directory)
                if not stat.S_ISDIR(directory.lstat().st_mode):
                    raise ValueError("observed startup directory changed type")
                with open_directory(directory) as fd, os.scandir(fd) as entries:
                    for entry in entries:
                        count += 1
                        if count > ENTRY_LIMIT:
                            raise ValueError("startup inventory entry limit exceeded")
                        path = directory / entry.name
                        if entry.name in ("site-packages", "dist-packages") and not app_site:
                            continue
                        if hook_name(entry.name) or (app_site and entry.name.endswith(".pth")):
                            record = self.capture(path, "binder name inventory", follow_hook=True)
                            if record["status"] == "absent":
                                raise ValueError("listed startup entry disappeared")
                            if entry.name in HOOKS and entry.is_dir(follow_symlinks=False):
                                self.capture(path / "__init__.py", "hook package initializer", follow_hook=True)
                                self.caches(path / "__init__.py")
                        if entry.is_dir(follow_symlinks=False):
                            if depth >= 16:
                                raise ValueError("startup inventory depth limit exceeded")
                            pending.append((path, depth + 1))
            except FileNotFoundError:
                self.problems.append({"path": str(directory), "error": "observed startup directory disappeared"})


def package_query(argv):
    valid_search = (len(argv) == 3 and argv[:2] == ["/usr/bin/dpkg-query", "-S"] and
                    argv[2].startswith("/") and not any(c in argv[2] for c in "*?[]\n\r\0"))
    valid_version = (len(argv) == 4 and argv[:3] == ["/usr/bin/dpkg-query", "-W", PACKAGE_FORMAT] and
                     re.fullmatch(r"[a-z0-9][a-z0-9+.-]*(?::[a-z0-9]+)?", argv[3]))
    if not (valid_search or valid_version):
        raise ValueError("unapproved query")
    result = {"argv": argv}
    try:
        ordinary_parents(Path(argv[0]))
        executable = Path(argv[0]).lstat()
        if not stat.S_ISREG(executable.st_mode) or executable.st_mode & 0o022:
            raise ValueError("package query executable is not an ordinary non-writable system file")
        result["executable_identity"] = identity(executable)
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                                cwd="/", close_fds=True)
    except (OSError, ValueError) as error:
        result.update(error=type(error).__name__ + ": " + str(error), output="", exit=None, cleanup_exit=None)
        return result
    data, deadline = bytearray(), time.monotonic() + 5
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ)
            while selector.get_map():
                if time.monotonic() >= deadline:
                    raise TimeoutError("package query exceeded five seconds")
                for key, _ in selector.select(0.05):
                    block = os.read(key.fd, 4096)
                    if not block:
                        selector.unregister(key.fileobj)
                    else:
                        data.extend(block)
                        if len(data) > 65536:
                            raise ValueError("package query output limit exceeded")
        result["exit"] = proc.wait(timeout=max(0.01, deadline - time.monotonic()))
    except (OSError, ValueError, TimeoutError, subprocess.TimeoutExpired) as error:
        result["error"] = type(error).__name__ + ": " + str(error)
    finally:
        try:
            if proc.poll() is None:
                proc.kill()
        except OSError as error:
            result["error"] = "package query kill failed: " + str(error)
        try:
            result["cleanup_exit"] = proc.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired) as error:
            result["cleanup_exit"] = None
            result["error"] = "package query did not reap: " + type(error).__name__
        finally:
            proc.stdout.close()
    result["output"] = bytes(data[:65536]).decode("utf-8", "backslashreplace")
    return result


PACKAGE_FORMAT = "-f=${binary:Package}\t${Version}\t${Architecture}\t${Status}\n${Conffiles}\n"


def provenance(collector, queries=None):
    paths = sorted({r["path"] for r in collector.records if r.get("identity") and
                    (hook_name(Path(r["path"]).name) or "link target" in r["role"] or
                     (Path(r["path"]).name.startswith("__init__.") and
                      (Path(r["path"]).parent.name in HOOKS or Path(r["path"]).parent.parent.name in HOOKS)) or
                     (r["role"].startswith("startup context") and Path(r["path"]).suffix == ".py"))})
    queries = [] if queries is None else queries
    packages = set()
    for path in paths[:32]:
        if any(c in path for c in "*?[]\n\r"):
            collector.problems.append({"path": path, "error": "not a literal dpkg query path"})
            continue
        query = package_query(["/usr/bin/dpkg-query", "-S", path])
        queries.append(query)
        if query.get("error") or query.get("exit") not in (0, 1):
            collector.problems.append({"path": path, "error": "package ownership query failed", "query": query})
        for line in query.get("output", "").splitlines():
            owner, separator, selected = line.rpartition(": ")
            if separator and selected == path:
                for package in owner.split(", "):
                    if re.fullmatch(r"[a-z0-9][a-z0-9+.-]*(?::[a-z0-9]+)?", package):
                        packages.add(package)
    if len(paths) > 32 or len(packages) > 16:
        collector.problems.append({"error": "package provenance query limit exceeded"})
    for package in sorted(packages)[:16]:
        query = package_query(["/usr/bin/dpkg-query", "-W", PACKAGE_FORMAT, package])
        queries.append(query)
        if query.get("error") or query.get("exit") != 0:
            collector.problems.append({"error": "package version query failed", "query": query})
    return queries


def runtime_facts():
    return {"version": sys.version, "executable": sys.executable, "prefix": sys.prefix,
            "base_prefix": sys.base_prefix, "exec_prefix": sys.exec_prefix,
            "base_exec_prefix": sys.base_exec_prefix, "sys_path": sys.path,
            "flags": repr(sys.flags), "cache_tag": sys.implementation.cache_tag,
            "optimization": sys.flags.optimize, "magic_hex": importlib.util.MAGIC_NUMBER.hex(),
            "hash_cache_policy": _imp.check_hash_based_pycs,
            "uname": list(os.uname()), "libc": os.confstr("CS_GNU_LIBC_VERSION"),
            "site_loaded": "site" in sys.modules,
            "hooks_loaded": [name for name in HOOKS if name in sys.modules]}


def collect(collector, stdlib, app, failed, support, facts=None):
    stdlib, app, failed, support = map(Path, (stdlib, app, failed, support))
    facts = runtime_facts() if facts is None else facts
    facts["builtin_frozen_candidates"] = {name: {"builtin": bool(_imp.is_builtin(name)), "frozen": _imp.is_frozen(name)}
                                            for name in (*HOOKS, "site", "importlib._bootstrap", "importlib._bootstrap_external")}
    facts["importlib_origins"] = {name: {"file": getattr(module, "__file__", None),
                                       "origin": getattr(getattr(module, "__spec__", None), "origin", None)}
                                  for name, module in (("bootstrap", sys.modules["importlib._bootstrap"]),
                                                       ("external", _bootstrap_external))}
    executables = list(dict.fromkeys([Path(sys.executable), Path(getattr(sys, "_base_executable", sys.executable)), app / "bin/python"]))
    allowed = {p.parent for p in executables} | {Path("/usr/bin"), app / "bin"}
    facts["interpreters"] = [collector.interpreter(p, allowed) for p in executables]
    for path in (stdlib / "site.py", stdlib / "importlib/_bootstrap.py",
                 stdlib / "importlib/_bootstrap_external.py", app / "pyvenv.cfg",
                 app / "bin/pyvenv.cfg", Path(sys.base_prefix) / "pyvenv.cfg",
                 stdlib.parent / "python311.zip", app / "lib64"):
        collector.capture(path, "startup context (not executed)", follow_hook=path.suffix == ".py")
    context_caches = [(stdlib / "site.py", _imp.is_frozen("site")),
                      (stdlib / "importlib/_bootstrap.py", facts["importlib_origins"]["bootstrap"]["origin"] == "frozen"),
                      (stdlib / "importlib/_bootstrap_external.py", facts["importlib_origins"]["external"]["origin"] == "frozen")]
    for path, frozen in context_caches:
        if not frozen:
            try:
                collector.caches(path)
            except (OSError, ValueError) as error:
                collector.problems.append({"path": str(path), "error": type(error).__name__ + ": " + str(error)})
    sites = [app / "lib/python3.11/site-packages", app / "lib/python3/dist-packages",
             app / "local/lib/python3.11/dist-packages"]
    roots = list(dict.fromkeys([Path(p) for p in sys.path if p and Path(p).is_absolute()] + sites))
    facts["conditional_roots"] = [str(p) for p in roots]
    facts["selection_limit"] = "Per-directory standard FileFinder only. Actual post-site order/effects require review of site.py, pyvenv.cfg and .pth; no site.main or hook was run."
    for root in roots:
        try:
            collector.candidates(root)
        except (OSError, ValueError) as error:
            collector.problems.append({"path": str(root), "error": type(error).__name__ + ": " + str(error)})
    for root, app_site in [(stdlib, False)] + [(p, True) for p in sites]:
        try:
            collector.inventory(root, app_site=app_site)
        except (OSError, ValueError) as error:
            collector.problems.append({"path": str(root), "error": type(error).__name__ + ": " + str(error)})
    for name in ("report.txt", "summary.json", "completion.json", "evidence.tar.gz", "phase-summary.json",
                 "input-identities.json", "phase-binding/call.json", "phase-binding/stdout", "phase-binding/stderr",
                 "EVIDENCE-SHA256SUMS", "evidence.tar.gz.sha256"):
        record = collector.capture(failed / name, "exact previously failed attempt")
        if name == "evidence.tar.gz":
            facts["failed_archive_matches_operator_digest"] = record.get("sha256") == FAILED_SHA
            if not facts["failed_archive_matches_operator_digest"]:
                collector.problems.append({"path": str(failed / name), "error": "failed archive absent, unreadable or digest mismatch"})
    for name in ("SHA256SUMS", "pi_target.py", "pi_guard.py", "run_pi_checks.py", "export-provenance.json"):
        collector.capture(support / name, "selected published support identity")
    return facts


def finish(collector, facts, queries):
    summary = {"kind": "DIAGNOSTIC ONLY, NOT APPLICATION VALIDATION", "facts": facts,
               "records": collector.records, "conditional_loader_choices": collector.selections,
               "ancestor_identities": collector.ancestors,
               "package_queries": queries, "unresolved": collector.problems,
               "limits": {"file_bytes": FILE_LIMIT, "total_bytes": TOTAL_LIMIT,
                          "records": RECORD_LIMIT, "entries_per_inventory": ENTRY_LIMIT},
               "trust": "Isolated CPython/stdlib and read-only system dpkg-query are trusted; not syscall isolation.",
               "prohibited": "No hook/cache execution, site.main, application import, network, installation, device or operational child."}
    (collector.output / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    report = ("Startup collection: DIAGNOSTIC ONLY\nInstalled application: NOT RUN\n"
              "Hook and cache code: NOT EXECUTED\nObservations: %d; unresolved: %d\n"
              "Actual site startup and loader reachability still require review.\n"
              "No hook is admitted by this report. Existing files/environments were not changed.\n"
              "Trust: isolated CPython/stdlib and read-only dpkg-query; not syscall isolation.\n"
              "Attach report.txt, summary.json and evidence.tar.gz. Preserve unresolved observations.\n"
              % (len(collector.records), len(collector.problems)))
    (collector.output / "report.txt").write_text(report)
    members = sorted(p for p in collector.output.iterdir() if p.is_file())
    archive = collector.output / "evidence.tar.gz"
    with tarfile.open(archive, "x:gz") as stream:
        for path in members:
            stream.add(path, arcname=path.name, recursive=False)
    with tarfile.open(archive, "r:gz") as stream:
        if stream.getnames() != [p.name for p in members]:
            raise ValueError("archive member mismatch")
        for member, path in zip(stream.getmembers(), members):
            if not member.isfile() or member.size != path.stat().st_size:
                raise ValueError("archive type or size mismatch")
            source_digest, archived_digest = hashlib.sha256(), hashlib.sha256()
            with path.open("rb") as original, stream.extractfile(member) as archived:
                for source in (original, archived):
                    digest = source_digest if source is original else archived_digest
                    for block in iter(lambda: source.read(65536), b""):
                        digest.update(block)
            if source_digest.digest() != archived_digest.digest():
                raise ValueError("archive content mismatch")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (collector.output / "evidence.sha256").write_text(digest + "  evidence.tar.gz\n")
    return digest


def main():
    if sys.argv[1:] or sys.version_info[:2] != (3, 11):
        sys.exit("Requires Python 3.11, -I -B -S, and no arguments.")
    ordinary_parents(TEST_ROOT / "placeholder")
    output = Path(tempfile.mkdtemp(prefix="startup-inspection-", dir=TEST_ROOT))
    stdlib = Path(sysconfig.get_path("stdlib"))
    collector = Collector(output, (stdlib, Path("/etc/python3.11"), Path("/usr/share/python3")))
    collector.capture(Path(__file__), "collector source identity")
    facts, queries = runtime_facts(), []
    try:
        collect(collector, stdlib, APP, FAILED, SUPPORT, facts)
        provenance(collector, queries)
    except Exception as error:
        collector.problems.append({"error": type(error).__name__ + ": " + str(error)})
    try:
        digest = finish(collector, facts, queries)
    except Exception as error:
        print("Diagnostic packaging failed:", type(error).__name__, str(error))
        print("Preserve partial directory:", output)
        return 2
    print("DIAGNOSTIC ONLY. Application checks were not run.")
    print("Report:", output / "report.txt")
    print("Evidence:", output / "evidence.tar.gz")
    print("SHA-256:", digest)
    print("Unresolved observations:", len(collector.problems))
    return 1 if collector.problems else 0


if __name__ == "__main__":
    sys.exit(main())
