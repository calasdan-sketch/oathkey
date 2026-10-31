"""Agent-driven key capture (experimental): the agent clicks Copy, this process takes the key.

The person tells the agent "connect GitHub". The agent opens the vendor's
key page with its own browser tools, makes the key and clicks the vendor's
own Copy button. THIS process (the MCP server, running as the person on
their own computer) sees the clipboard change, takes the new key-shaped
value, EMPTIES the clipboard (and checks that it is empty), tests the key
with the vendor, stores it (.env or the OS keychain) and tells the agent
only: stored, which variable, where, how long, which account. The key is
never in a tool result, an error, a log, the chat or on screen.

States an answer can carry (`state`):
  consent_needed   the person has not allowed this; no window could be shown
  consent_pending  a confirmation window is on the person's screen
  consent_expired  the window closed by itself (5 min); tell the person, they can ask again
  consent_granted / replace_granted   the person said yes; call start (replace_granted: with replace=true)
  consent_denied   the person said no
  unavailable      no usable clipboard here (reason in the message)
  unsupported_gateless  the service has no documented key format to recognise
  refused          not allowed (clipboard history, recipe of your own, limits)
  busy             another capture is running
  already_stored   a key exists; replace needs the person's separate yes
  waiting          armed: waiting for the Copy
  validating       a key was taken; the vendor is being asked
  confirming       the key is valid; the person is asked, in a window, to confirm the account
  storing          valid; being written (cannot be cancelled now)
  stored           done
  failed / timeout / cancelled   nothing was saved
  idle             nothing has been started

Guards: the person's yes (a window of the OS, remembered in this server's
memory for the session only; or the terminal command `allow-agent`, kept in a
signed file that is advisory - see consent.py), then a second window that
shows the account the key belongs to, built-in recipes with a key format only, one at a time, 10-180 s,
six starts an hour, only a value that CHANGES the clipboard after arming and
has the service's key format, a rejected or unstorable key is kept nowhere,
and clipboard history (Windows) or an unknown state of it refuses.
"""

from __future__ import annotations

import datetime
import os
import re
import secrets
import threading
import time

from . import clipboard as clipboard_mod
from . import connect as connect_mod
from . import consent as consent_mod
from . import dialog as dialog_mod
from . import ledger as ledger_mod
from . import manifest as manifest_mod
from . import recipes as recipes_mod
from . import redact as redact_mod
from . import store as store_mod
from . import validate as validate_mod

MIN_TIMEOUT = 10.0
DEFAULT_TIMEOUT = 120.0
MAX_TIMEOUT = 180.0
DEFAULT_STATUS_WAIT = 25.0
MAX_STATUS_WAIT = 45.0
STARTS_PER_HOUR = 6
DIALOGS_PER_HOUR = 4
POLL = 0.1
REPLACE_WINDOW = 300.0

# the grant helpers live in consent.py; kept here under their old names
grant = consent_mod.grant
revoke = consent_mod.revoke
consent_for = consent_mod.consent_for
grants_for = consent_mod.grants_for
project_root = manifest_mod.project_root


def length_class(n: int) -> str:
    return "short (under 32 characters)" if n < 32 else (
        "medium (32 to 63 characters)" if n < 64 else "long (64 characters or more)")


ORPHAN = ("If a key was already created at the vendor and not captured, it still "
          "exists there: ask the person to delete it on the vendor's page.")
MANAGERS = ("A clipboard manager or clipboard history app may keep its own copy of "
            "what is copied; this tool cannot remove that.")


def environment_problem(env=None, read=None) -> str | None:
    """Why this is not the person's desktop (SSH, WSL), or None."""
    env = os.environ if env is None else env
    if env.get("SSH_CONNECTION") or env.get("SSH_TTY"):
        return ("this server runs inside an SSH session, so its clipboard is not the "
                "person's desktop clipboard")
    try:
        text = (read or (lambda: open("/proc/version", encoding="utf-8").read()))()
    except OSError:
        return None
    if "microsoft" in text.lower():
        return ("this server runs inside WSL; the Linux clipboard tools here cannot see "
                "the Windows clipboard")
    return None


class _Capture:
    def __init__(self, slug, recipe, root, env_file, store, timeout, started):
        self.id = secrets.token_hex(4)
        self.slug = slug
        self.recipe = recipe
        self.root = root
        self.env_file = env_file
        self.store = store
        self.deadline = started + timeout
        self.state = "waiting"
        self.message = ""
        self.waiting_for = ""
        self.ignored = 0
        self.stored_in: list[str] = []
        self.length_classes: list[str] = []
        self.note = None
        self.account = None
        self.account_confirmed = None
        self.stored_key_note = None
        self.history_note = None
        self.clipboard_warning = None
        self.stale_note = None
        self.finished_at = None
        self.cancel = threading.Event()
        self.done = threading.Event()
        self.cond = threading.Condition()

    def set(self, state: str, message: str | None = None) -> None:
        with self.cond:
            self.state = state
            if message is not None:
                self.message = message
            if state in ("stored", "failed", "timeout", "cancelled"):
                self.finished_at = datetime.datetime.now(datetime.timezone.utc).replace(
                    microsecond=0).isoformat()
            self.cond.notify_all()

    def public(self) -> dict:
        out = {"capture_id": self.id, "service": self.slug, "state": self.state,
               "env_vars": recipes_mod.env_vars(self.recipe)}
        if self.message:
            out["message"] = self.message
        if self.state == "waiting":
            out["waiting_for"] = self.waiting_for
        if self.ignored:
            out["ignored_clipboard_changes"] = self.ignored
        if self.state == "stored":
            out["stored"] = True
            out["stored_in"] = self.stored_in
            out["key_length"] = self.length_classes
            if self.account:
                out["account"] = self.account
            if self.account_confirmed is not None:
                out["account_confirmed_by_person"] = self.account_confirmed
        if self.note:
            out["vendor_note"] = self.note
        if self.stored_key_note:
            out["stored_key_note"] = self.stored_key_note
        for key, value in (("clipboard_history_warning", self.history_note),
                           ("clipboard_warning", self.clipboard_warning),
                           ("clipboard_note", self.stale_note)):
            if value:
                out[key] = value
        if self.finished_at:
            out["finished_at"] = self.finished_at
        return out


class _Job:
    """A confirmation window shown to the person, answered off the main thread."""

    def __init__(self, kind, root, slug, now=0.0):
        self.kind, self.root, self.slug = kind, root, slug
        self.note = None                # extra words for the agent when the answer comes
        self.soft = False               # a No that might have been a closed window
        self.expired = False            # the window closed by itself: nobody answered
        self.answer = None              # True / False; None = open, or nobody could/did answer
        self.done = threading.Event()
        self.finished = None            # self.now() when answered


class Manager:
    """One capture at a time. Everything the outside world touches is a
    parameter, so tests use a fake clipboard, a fake vendor and a fake window."""

    def __init__(self, backend=clipboard_mod.backend,
                 validate_fn=validate_mod.validate_key,
                 history_fn=clipboard_mod.history_warning,
                 now=time.monotonic, sleep=time.sleep, poll: float = POLL,
                 consent_file: str | None = None, secret_store=None,
                 timeout_limits: tuple[float, float] = (MIN_TIMEOUT, MAX_TIMEOUT),
                 starts_per_hour: int = STARTS_PER_HOUR, store_factory=None,
                 record_fn=ledger_mod.record, ask_person=dialog_mod.confirm,
                 window_available=dialog_mod.available, env_problem=environment_problem,
                 default_store: str = "env", clear_wait: float = 3.0,
                 window_note=dialog_mod.why_unavailable, client_name=None):
        self.backend = backend
        self.validate_fn = validate_fn
        self.history_fn = history_fn
        self.now = now
        self.sleep = sleep
        self.poll = poll
        self.consent_file = consent_file
        self.secret_store = secret_store
        self.limits = timeout_limits
        self.starts_per_hour = starts_per_hour
        self.store_factory = store_factory
        self.record_fn = record_fn
        self.ask_person = ask_person
        self.window_available = window_available
        self.env_problem = env_problem
        self.default_store = default_store
        self.clear_wait = clear_wait
        self.window_note = window_note
        self.client_name = client_name         # None: whoever said hello in `initialize`
        self._lock = threading.Lock()
        self._current: _Capture | None = None
        self._job: _Job | None = None
        self._dialogs: list[float] = []
        self._denied: dict = {}
        self._replace_ok: dict = {}
        self._session: dict = {}        # consent given in a window: memory only, this session
        self._starts: list[float] = []

    # ---- consent helpers

    def _who(self):
        return dialog_mod.client_label(self.client_name)

    def _stored_status(self, recipe, env_file, store, slug) -> str:
        """Does the key stored now still work? "dead" only when the vendor
        itself rejects it; "ok" when it works; "unknown" for everything else
        (no validator, can't read it, vendor unreachable). The key is read and
        sent to the vendor, never shown or kept."""
        spec = recipe.get("validate")
        if not spec:
            return "unknown"
        values = {}
        try:
            for field in recipes_mod.fields(recipe):
                if store == "keychain":
                    from . import keychain as keychain_mod
                    value = keychain_mod.read(slug, field["env_var"])
                else:
                    value = store_mod.load_env(env_file).get(field["env_var"])
                if not value:
                    return "unknown"
                values[field["name"]] = value
            single = len(values) == 1 and recipes_mod.DEFAULT_FIELD in values
            verdict = self.validate_fn(spec, values[recipes_mod.DEFAULT_FIELD] if single else dict(values),
                                       timeout=6.0)
        except Exception:
            return "unknown"
        finally:
            values.clear()
        status = getattr(verdict, "status", None)
        if status == "invalid":
            return "dead"
        return "ok" if verdict else "unknown"

    def _note(self):
        try:
            return self.window_note()
        except Exception:
            return None

    def _consent(self, root, slug):
        """The grant for this project and service. When a window can be shown
        ONLY the window's yes of this session counts (memory): a file on disk -
        even a well-formed one - is ignored, because a file is exactly what an
        agent that can write files could forge. The terminal grant in the signed
        file applies only where no window can be shown (SSH, headless)."""
        mine = self._session.get((consent_mod.project_key(root), slug))
        if mine is not None:
            return mine
        if self.window_available():
            return None
        return consent_mod.consent_for(root, slug, self.consent_file, self.secret_store)

    def _ask(self, kind, root, slug, recipe, note=None) -> dict:
        """Put a window in front of the person (once; not again right after a
        'no'); the answer is recorded by this server, never by the agent."""
        key = (consent_mod.project_key(root), slug, kind)
        with self._lock:                        # check and set as one step: one window at a time
            t = self.now()
            job = self._job
            if job is not None and not job.done.is_set():
                return {"state": "consent_pending", "service": slug, "message": _PENDING}
            if t - self._denied.get(key, -1e9) < 600:
                return {"state": "consent_denied", "service": slug, "message": (
                    "The person said no. Do not ask again unless they bring it up.")}
            self._dialogs[:] = [d for d in self._dialogs if t - d < 3600]
            if len(self._dialogs) >= DIALOGS_PER_HOUR:
                return {"state": "refused", "service": slug,
                        "message": "Too many permission windows were shown in the last hour."}
            self._dialogs.append(t)
            job = _Job(kind, root, slug)
            job.note = note
            self._job = job
            if self._current is not None and self._current.done.is_set():
                self._current = None            # the old result must not hide this question
        display = recipes_mod.printable(recipe["display"], words=True)
        if kind == "consent":
            title, text = dialog_mod.consent_window(display, root, self._who())
        else:                                   # "replace" and "replace_all" are one question
            title, text = dialog_mod.replace_window(display, root, self._who())

        def run():
            try:
                raw = self.ask_person(title, text)
                if raw is dialog_mod.EXPIRED:
                    job.expired = True
                if raw is dialog_mod.SOFT_NO:
                    job.soft = True             # told "no" for now, but never remembered
                job.answer = None if (raw is None or raw is dialog_mod.EXPIRED) else bool(raw)
            except Exception:
                job.answer = None               # a helper that failed is not the person's "no"
            try:
                if job.answer is None:
                    pass                        # no window / nobody answered: not a "no"; may be asked again
                elif job.answer and kind in ("consent", "replace_all"):
                    if kind == "replace_all":
                        self._replace_ok[key[:2] + ("replace",)] = self.now()
                    self._session[key[:2]] = {
                        "project": os.path.realpath(root), "service": slug,
                        "clipboard_history_ok": False, "via": "window",
                        "granted": datetime.datetime.now(datetime.timezone.utc).replace(
                            microsecond=0).isoformat()}
                elif job.answer:
                    self._replace_ok[key] = self.now()
                elif job.soft:
                    pass                        # maybe just closed: do not shut the door for 10 minutes
                else:
                    self._denied[key] = self.now()
                    if kind == "replace_all":
                        self._denied[key[:2] + ("consent",)] = self.now()
            except Exception:
                job.answer = None
            finally:
                job.finished = self.now()
                job.done.set()
        threading.Thread(target=run, daemon=True).start()
        return {"state": "consent_pending", "service": slug, "message": _PENDING}

    # ---- the three actions

    def start(self, slug: str, recipe: dict, cwd: str | None, timeout=None,
              replace: bool = False) -> dict:
        with self._lock:
            if self._current is not None and self._current.done.is_set():
                self._current = None            # an old result is not news any more
        root = project_root(cwd)
        if recipe.get("_builtin") is not True:
            return _refused("agent capture works only with the recipes that ship with "
                            "stuntkey; a recipe of your own is not allowed. Ask the "
                            "person to run `stuntkey connect " + slug + "` themselves.")
        fields = recipes_mod.fields(recipe)
        problem = _gate_problem(recipe, fields)
        if problem:
            return {"state": "unsupported_gateless", "service": slug, "message": problem}
        why = self.env_problem()
        if why:
            return _unavailable(slug, why)
        try:
            get, clear = self.backend()
        except clipboard_mod.Unavailable as e:
            return _unavailable(slug, str(e))
        grant_ = self._consent(root, slug)
        if grant_ is None:
            if self.window_available():
                kind, note = "consent", None
                if replace:
                    # one question, not two: the person is asked once about REPLACING
                    env_file0, store0 = _where(root, slug, {}, self.default_store)
                    if env_file0 is not None and _present(recipe, env_file0, store0, slug):
                        if self._stored_status(recipe, env_file0, store0, slug) == "dead":
                            note = DEAD_KEY
                        else:
                            kind = "replace_all"
                return self._ask(kind, root, slug, recipe, note if replace else None)
            return _need_consent(slug, self._note())
        warning = None
        try:
            warning = self.history_fn()
        except Exception:
            warning = "Whether a clipboard history is on could not be checked."   # fail closed
        if warning and not grant_.get("clipboard_history_ok"):
            return {"state": "refused", "service": slug, "clipboard_history": True,
                    "message": (
                        "Clipboard history is on (or could not be checked): it would keep a "
                        "copy of the key after the clipboard is emptied, and nothing can "
                        "remove that copy. Nothing was started. Tell the person: either turn "
                        "clipboard history off (Settings > System > Clipboard) and ask again, "
                        "or - if they accept the risk and no window can be shown here - run in "
                        "their own terminal: stuntkey allow-agent " + slug
                        + " --allow-clipboard-history (that terminal grant is not "
                        "used while a window can be shown)")}
        env_file, store = _where(root, slug, grant_, self.default_store)
        if env_file is None:
            return _refused("the key file for this project is not allowed; ask the person "
                            "to look at stuntkey.json or re-run allow-agent.")
        if store == "env":
            try:
                store_mod.check_env_file(env_file)
            except OSError as e:
                return _refused(f"the key file cannot be used ({e.strerror or 'refused'}); "
                                "nothing was started. Ask the person to look at it.")
        replace_key = None
        dead_note = None
        present = _present(recipe, env_file, store, slug)
        if present:
            key = (consent_mod.project_key(root), slug, "replace")
            replace_key = key
            if not replace:
                return {"state": "already_stored", "service": slug,
                        "env_vars": recipes_mod.env_vars(recipe), "message": (
                            "A key is already stored. Do not capture another unless the "
                            "person asked to replace it (then pass replace=true and they "
                            "will be asked in a window).")}
            if self._stored_status(recipe, env_file, store, slug) == "dead":
                dead_note = DEAD_KEY            # nothing to protect: no replace question
                replace_key = None
            elif self.now() - self._replace_ok.get(key, -1e9) > REPLACE_WINDOW:
                if self.window_available():
                    return self._ask("replace", root, slug, recipe)
                return _refused("replacing a stored key needs the person's yes in a window, "
                                "and none can be shown here. Ask them to run: stuntkey "
                                f"rotate {slug}")
        with self._lock:
            if self._current is not None and not self._current.done.is_set():
                return {"state": "busy", "service": self._current.slug,
                        "message": "A capture is already running. Use action=status "
                                   "or action=cancel; only one runs at a time."}
            t = self.now()
            self._starts[:] = [s for s in self._starts if t - s < 3600]
            if len(self._starts) >= self.starts_per_hour:
                return {"state": "refused", "service": slug, "message": (
                    "Too many captures were started in the last hour. Wait, or ask "
                    "the person to run stuntkey connect " + slug + " themselves.")}
            low, high = self.limits
            try:
                seconds = float(timeout) if timeout is not None else DEFAULT_TIMEOUT
            except (TypeError, ValueError):
                seconds = DEFAULT_TIMEOUT
            seconds = max(low, min(high, seconds)) if seconds == seconds else DEFAULT_TIMEOUT
            self._starts.append(t)
            cap = _Capture(slug, recipe, root, env_file, store, seconds, t)
            cap.history_note = warning
            cap.stored_key_note = dead_note
            cap.waiting_for = "the key" if len(fields) == 1 else f"the {fields[0]['label']}"
            self._current = cap
            self._job = None
            if replace_key is not None:
                self._replace_ok.pop(replace_key, None)     # used up only now that it is armed
        try:
            # The "before" picture is taken HERE, before start() returns: a Copy
            # a moment later must count as new, not as old.
            seen = _snapshot(get, clear, _gate(fields[0]), cap, self.clear_wait)
            threading.Thread(target=self._run, args=(cap, get, clear, seen), daemon=True).start()
        except Exception:
            cap.set("failed", "Capture could not be armed (the clipboard did not answer). "
                              "Nothing was started.")
            cap.done.set()
            return cap.public()
        out = cap.public()
        out["timeout_seconds"] = int(seconds)
        out["message"] = ("Armed. Now, in the browser, create the key and click the vendor's "
                          "Copy button - nothing else. Then call capture_key with "
                          "action=status (it waits up to 25 seconds and returns as soon as "
                          "anything changes). " + MANAGERS)
        return out

    def status(self, wait=None) -> dict:
        cap = self._current
        job = self._job
        try:
            seconds = DEFAULT_STATUS_WAIT if wait is None else float(wait)
        except (TypeError, ValueError):
            seconds = DEFAULT_STATUS_WAIT
        seconds = max(0.0, min(MAX_STATUS_WAIT, seconds)) if seconds == seconds else DEFAULT_STATUS_WAIT
        if job is not None and (cap is None or cap.done.is_set()):
            if not job.done.is_set() and seconds:
                job.done.wait(seconds)          # the person is answering: wait for it
            return _job_state(job, self.now(), self._note())
        if cap is None:
            return {"state": "idle", "message": "No capture has been started."}
        end = time.monotonic() + seconds
        with cap.cond:
            entry = cap.state
            while not cap.done.is_set() and cap.state == entry:
                left = end - time.monotonic()
                if left <= 0:
                    break
                cap.cond.wait(left)
        return cap.public()

    def cancel(self) -> dict:
        cap = self._current
        if cap is None or cap.done.is_set():
            return {"state": "idle", "message": "Nothing is running."}
        if cap.state == "storing":
            out = cap.public()
            out["cancel"] = "too_late"
            out["message"] = "The key is being written now; it cannot be cancelled."
            return out
        cap.cancel.set()
        cap.done.wait(15)
        out = cap.public()
        if not cap.done.is_set():
            out["message"] = ("Cancel requested; the key will not be stored. "
                              "It is still being checked with the vendor.")
        return out

    def shutdown(self) -> None:
        """The server is ending: stop any armed capture, leave nothing on the clipboard."""
        cap = self._current
        if cap is not None and not cap.done.is_set():
            cap.cancel.set()
            cap.done.wait(5)
            try:
                get, clear = self.backend()
                clipboard_mod.clear_verified(get, clear, wait=1.0)
            except Exception:
                pass

    # ---- the worker

    def _run(self, cap: _Capture, get, clear, seen) -> None:
        values: dict[str, str] = {}
        try:
            self._collect(cap, get, clear, values, seen)
            if cap.state == "waiting":
                self._finish(cap, values)
        except Exception:                       # never lets the key into a message
            cap.set("failed", "Capture failed unexpectedly. Nothing was saved.")
        finally:
            values.clear()
            if cap.state in ("waiting", "validating", "confirming", "storing"):
                cap.set("failed", "Capture failed unexpectedly. Nothing was saved.")
            cap.done.set()

    def _collect(self, cap, get, clear, values, seen) -> None:
        fields = recipes_mod.fields(cap.recipe)
        single = len(fields) == 1 and fields[0]["name"] == recipes_mod.DEFAULT_FIELD
        sequence = getattr(get, "sequence", None)
        last_seq = None
        for index, field in enumerate(fields):
            cap.waiting_for = "the key" if single else f"the {field['label']}"
            gate = _gate(field)
            if index:
                seen = ""                       # just verified empty: a fast second Copy counts
            while True:
                if cap.cancel.is_set():
                    cap.set("cancelled", "Cancelled. Nothing was saved.")
                    return
                if self.now() >= cap.deadline:
                    cap.set("timeout", (
                        "No key was copied in time. Nothing was saved. Possible reasons: the "
                        "browser needed a login, 2FA, a CAPTCHA or a password (the person does "
                        "those); the page's Copy click did not reach the system clipboard (the "
                        "browser window may need focus or clipboard permission) - then ask the "
                        "person to press the vendor's Copy button once themselves, and call "
                        "capture_key again. " + ORPHAN))
                    return
                self.sleep(self.poll)
                if sequence is not None:
                    try:
                        number = sequence()
                    except Exception:
                        number = None
                    if number is not None and number == last_seq:
                        continue
                    last_seq = number
                try:
                    current = (get() or "").strip()
                except Exception:
                    continue                    # unreadable this moment: look again
                if current == seen:
                    continue
                seen = current
                if not current or current in values.values():
                    continue
                if clipboard_mod.looks_like(current, gate):
                    values[field["name"]] = current
                    ok = clipboard_mod.clear_verified(get, clear, self.clear_wait)
                    if not ok:
                        cap.clipboard_warning = (
                            "The clipboard could NOT be emptied: the key may still be on it. "
                            "Ask the person to copy some other text now to replace it.")
                    break
                cap.ignored += 1                # something else was copied: not used
            current = None

    def _finish(self, cap, values) -> None:
        recipe = cap.recipe
        fields = recipes_mod.fields(recipe)
        single = len(fields) == 1 and fields[0]["name"] == recipes_mod.DEFAULT_FIELD
        scrub = redact_mod.Redactor(list(values.values()))
        cap.set("validating", "A key was taken. Asking the vendor whether it works.")
        for value in values.values():
            if store_mod.unsafe_reason(value):
                cap.set("failed", "The copied value has a character that cannot be stored "
                                  "safely, so it is not a usable key. Nothing was sent or saved.")
                return
        if cap.cancel.is_set():
            cap.set("cancelled", "Cancelled before the key was checked. Nothing was saved.")
            return
        try:
            ok = self.validate_fn(recipe["validate"],
                                  values[recipes_mod.DEFAULT_FIELD] if single else dict(values))
        except validate_mod.UnsendableKey:
            cap.set("failed", "The copied value cannot be used as a key. Nothing was saved.")
            return
        except Exception as e:                  # a vendor error is never allowed to carry the key
            cap.set("failed", ("The vendor could not be reached or answered oddly: "
                               + scrub.text(recipes_mod.printable(e))[:200]
                               + ". Nothing was saved. " + ORPHAN))
            return
        if not ok:
            cap.set("failed", "The vendor rejected the copied value - it was not the key, or "
                              "it is expired. Nothing was saved. Check which button was "
                              "clicked, then start again. " + ORPHAN)
            return
        if cap.cancel.is_set():
            cap.set("cancelled", "Cancelled before saving. The key was not stored. " + ORPHAN)
            return
        cap.note = getattr(ok, "note", None) and scrub.text(
            recipes_mod.printable(ok.note, words=True))
        identity = getattr(ok, "identity", None)
        cap.account = identity and scrub.text(recipes_mod.printable(identity))
        if self.window_available():
            cap.set("confirming", "The key is valid. A window asks the person to confirm "
                                  "which account it belongs to.")
            title, text = dialog_mod.account_window(
                recipes_mod.printable(recipe["display"], words=True), cap.account, cap.root)
            try:
                raw = self.ask_person(title, text)
            except Exception:
                raw = None
            cap.account_confirmed = raw is True
            if raw is not True:
                cap.set("failed", (
                    "The account window closed without an answer. TELL THE "
                    "PERSON it expired and that they can simply ask you again. "
                    if raw is dialog_mod.EXPIRED else
                    "The account window was closed without a clear answer; nothing is stored. "
                    "Tell the person they can ask again. " if raw is dialog_mod.SOFT_NO else
                    "The person did not confirm the account (or the window could not be "
                    "shown). " if raw is None else "The person said this is not their account. ")
                    + "The key was NOT stored. " + ORPHAN)
                return
            if cap.cancel.is_set():
                cap.set("cancelled", "Cancelled before saving. The key was not stored. " + ORPHAN)
                return
        cap.set("storing", "The key is valid. Saving it.")
        store_fn = (self.store_factory or _default_store)(recipe, cap.env_file, cap.store)
        saved = []
        try:
            for field in fields:
                saved.append(store_fn(field["env_var"], values[field["name"]]))
        except Exception as e:
            why = scrub.text(recipes_mod.printable(getattr(e, "strerror", None) or e))[:200]
            cap.set("failed", (
                f"The key was valid but could NOT be saved ({why}). It is not kept anywhere. "
                + ("Only part was written; ask the person to run "
                   f"stuntkey forget {cap.slug}." if saved else "Nothing was written.")))
            return
        cap.stored_in = [scrub.text(_first_line(d)) for d in saved]
        cap.length_classes = [length_class(len(v)) for v in values.values()]
        emptied = "" if cap.clipboard_warning else "The clipboard was emptied. "
        cap.set("stored", "Stored. " + emptied + "The key was not shown to you and must not "
                          "be looked for. Use the variable by name.")
        try:
            self.record_fn(cap.root, cap.slug, cap.store)
        except Exception:
            pass


_PENDING = ("A confirmation window was put on the person's screen (it may be behind other "
            "windows). Ask them to answer it, then call capture_key again with action=status "
            "or action=start. Do not open the key page yet.")


STALE_AFTER = 600.0
DEAD_KEY = ("The key stored now no longer works (the vendor rejects it), so nothing valuable is "
            "being replaced. Tell the person that.")


def _job_state(job: _Job, now: float, note: str | None = None) -> dict:
    if not job.done.is_set():
        return {"state": "consent_pending", "service": job.slug, "message": _PENDING}
    if job.finished is not None and now - job.finished > STALE_AFTER:
        return {"state": "idle", "message": "The earlier question to the person is no longer current."}
    if job.answer is None and job.expired:
        return _expired(job.slug)
    if job.answer is None:
        return _need_consent(job.slug, note, window_failed=True)
    extra = (" " + job.note) if getattr(job, "note", None) else ""
    if job.answer:
        if job.kind == "consent":
            return {"state": "consent_granted", "service": job.slug,
                    "message": "The person said yes. Call capture_key with action=start"
                               + (" and replace=true" if extra else "") + " now." + extra}
        return {"state": "replace_granted", "service": job.slug,
                "message": "The person said yes to replacing the key. Call capture_key with "
                           "action=start AND replace=true now."}
    if job.soft:
        return {"state": "consent_denied", "service": job.slug, "message": (
            "The window went away with a No - or the person closed it; the tool cannot tell "
            "which. Nothing was changed. Do not ask again unless the person brings it up.")}
    return {"state": "consent_denied", "service": job.slug, "message": "The person said no."}


def _expired(slug: str) -> dict:
    return {"state": "consent_expired", "service": slug, "message": (
        "The permission window closed without an answer (it stays open for 5 minutes, or the "
        "person closed it without choosing). That is not a refusal and nothing was changed. "
        "TELL THE PERSON the window expired and that they can simply ask you again; then call capture_key with "
        "action=start when they do. Do not open the key page or click anything yet.")}


def _need_consent(slug: str, note: str | None = None, window_failed: bool = False) -> dict:
    if window_failed:
        return {"state": "consent_needed", "service": slug, "message": (
            "The permission window could not be shown or was not answered in time. That is "
            "not a refusal: call capture_key with action=start to ask again. A terminal "
            "`allow-agent` grant is NOT used while a window can be shown. If the window keeps "
            "failing, the person can restart the stuntkey server with the environment "
            "variable STUNTKEY_NO_WINDOW=1 to use the terminal route instead. Until then do "
            "not open the key page or click anything.")}
    return {"state": "consent_needed", "service": slug, "message": ((note + " " if note else "") + (
        "The person has not allowed agent-driven key capture for this service in this "
        "project, and no window could be answered here. Ask them, in plain words, whether you "
        "may. If they agree they run, in their OWN terminal: stuntkey allow-agent " + slug
        + " - then call capture_key again. (That terminal permission is weaker than the "
        "window: a program can fake a terminal and it is kept in a file. A window only "
        "counts for this session.) Until then do not open the key page or click anything."))}


def _gate(field: dict):
    """The key format a copied value must have: the recipe's STRICT capture
    pattern, else its accept pattern, else its detect pattern when that is a
    documented ("known") shape; else None."""
    return field.get("capture_accept") or field.get("accept") or (field.get("detect")
                                   if field.get("detect_confidence") == "known" else None)


def _gate_problem(recipe: dict, fields: list) -> str | None:
    if recipe.get("capture_safe") is True and not len(fields) > 1:
        return None
    gates = [_gate(f) for f in fields]
    if any(g is None for g in gates):
        return ("This service has no documented key format, so a copied value cannot be "
                "recognised as its key (anything on the clipboard could be taken). Agent "
                "capture is not available for it: ask the person to run `stuntkey "
                f"connect {recipe['service']}` themselves.")
    if len(set(gates)) != len(gates):
        return ("This service's values look alike, so they could be swapped; agent capture "
                "is not available for it. Ask the person to run `stuntkey connect "
                f"{recipe['service']}`.")
    return None


def _snapshot(get, clear, gate, cap=None, wait: float = 3.0) -> str:
    """What is on the clipboard now is OLD. A value shaped like THIS service's
    key is wiped (so that copying it again counts as a change - said in the
    result); anything else is left alone and just remembered as 'before'."""
    seen = (get() or "").strip()
    if seen and clipboard_mod.looks_like(seen, gate):
        clipboard_mod.clear_verified(get, clear, wait)
        if cap is not None:
            cap.stale_note = ("A value shaped like this service's key was already on the "
                              "clipboard; it was removed and not used.")
        return ""
    return seen


def _first_line(text: str) -> str:
    return (text or "").splitlines()[0] if text else ""


def _refused(message: str) -> dict:
    return {"state": "refused", "message": message}


def _unavailable(slug: str, reason: str) -> dict:
    return {"state": "unavailable", "service": slug, "message": (
        "Agent capture cannot be used here: " + re.sub(r"\s+", " ", reason)[:200] + ". Ask "
        "the person to run: stuntkey connect " + slug + " in their own terminal.")}


def _where(root: str, slug: str, grant_: dict, default_store: str):
    """(env file, store). The file is the project's .env unless the person's
    grant names another .env-style file; the manifest only chooses the store."""
    name = grant_.get("env_file") or ".env"
    if manifest_mod.env_file_problem(name) is not None:
        return None, None
    store = default_store
    path = os.path.join(root, manifest_mod.FILE_NAME)
    if os.path.isfile(path):
        try:
            data = manifest_mod.load(path)
        except manifest_mod.ManifestError:
            data = {"services": []}
        for item in data.get("services", []):
            if item["service"] == slug:
                store = item.get("store", store)
    return os.path.join(root, *name.split("/")), store


def _present(recipe: dict, env_file: str, store: str, slug: str) -> bool:
    if store == "keychain":
        from . import keychain as keychain_mod
        try:
            return all(keychain_mod.read(slug, v) for v in recipes_mod.env_vars(recipe))
        except Exception:
            return False
    from . import presence as presence_mod
    have = presence_mod.env_names(env_file)
    return all(v in have for v in recipes_mod.env_vars(recipe))


def _default_store(recipe: dict, env_file: str, store: str):
    """store_fn for an agent capture. Never asks the person anything: a
    keychain that fails does not fall back to a plain file."""
    if store == "keychain":
        import io
        from . import cli as cli_mod
        return cli_mod.keychain_store(recipe, env_file, out=io.StringIO(),
                                      interactive=lambda: False)
    return connect_mod.store_in_env_file(env_file)


_MANAGER: Manager | None = None


def default_manager() -> Manager:
    global _MANAGER
    if _MANAGER is None:
        _MANAGER = Manager()
    return _MANAGER


def set_manager(manager: Manager | None) -> None:
    global _MANAGER
    _MANAGER = manager


def shutdown() -> None:
    """Called when the server ends."""
    if _MANAGER is not None:
        _MANAGER.shutdown()
