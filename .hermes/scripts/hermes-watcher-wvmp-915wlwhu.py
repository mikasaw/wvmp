"""hermes-watcher for MIT-389 (WVmpVerifier) + MIT-390 (WVmpCppDev)
WVmp project dev-verifier chain monitoring.
- 600s INTERVAL (per multica-orchestration-patterns sweet spot)
- FIX-1: in_progress + cppdev task completed -> in_review
- FIX-2: in_review + verifier task not running/queued -> assign + rerun (dedup FIX-2-SKIP)
- FIX-3: verifier Accept (ACCEPT verdict or re-fire confirmation) -> done
- FIX-2-SKIP (v3.18.2): Accept-history check, skip if verifier already Accept
- Workspace context: MIT-373 8ed50b0 SSE fix, MIT-389 verifier gate harden,
  MIT-390 backlog template update. 2 active issues for now.
"""
import os, subprocess, json, time, pathlib, sys
from datetime import datetime

MC = r"C:\Users\www\AppData\Local\Programs\@multicadesktop\resources\app.asar.unpacked\resources\bin\multica.exe"
PROJECT = "a1773c64-4a70-4163-b79e-7dd7d601d073"  # WVmp project
CPPDEV  = "03217ff2-9456-4237-aa7b-485c8fcdd8dd"  # WVmpCppDev
VERIFIER = "0326c8dd-7869-4e04-b6c1-f945746aac29"  # WVmpVerifier
INTERVAL = 600  # 10 min

# Targeted issues (don't scan whole project, 2 active)
TARGET_ISSUE_IDS = [
    "01a04627-5c96-7b42-a336-e805d4df7aed",  # MIT-389 -> WVmpVerifier
    "01a04627-5f95-7ba4-a3ab-0ac6cc4d399d",  # MIT-390 -> WVmpCppDev
]

LOG_DIR = pathlib.Path(os.environ.get("TEMP", r"C:\Users\www\AppData\Local\Temp"))
LOG_PATH = LOG_DIR / f"hermes-watcher-wvmp-{datetime.now().strftime('%Y%m%d-%H%M%S')}.log"

def mc(args, t=60):
    return subprocess.run(
        [MC] + args + ["--output", "json"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=t
    )

def log(fp, msg, kind=None):
    line = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line, flush=True)
    fp.write(line + "\n"); fp.flush()
    # Emit a single, unique, watch_patterns-friendly marker per FIX action.
    # Hermes terminal watch_patterns requires a literal substring match on stdout.
    # The kind-tagged line is the ONLY line with the prefix below; combined
    # with a stable 16-byte uuid prefix per kind, we keep collisions off the
    # 15s/cooldown strike limit (FIX events are rare one-shots, not loops).
    if kind in ("FIX1", "FIX2", "FIX3"):
        sys.stdout.write(f"HERMES_WATCH_PATTERNS_HIT kind={kind} uuid={fp.name.split('-')[-1].split('.')[0][:8]}\n")
        sys.stdout.flush()

def issue_get(iid):
    r = mc(["issue", "get", iid])
    try:
        return json.loads(r.stdout) if r.returncode == 0 else None
    except Exception:
        return None

def agent_tasks(agent_id):
    r = mc(["agent", "tasks", agent_id])
    try:
        d = json.loads(r.stdout)
        return d if isinstance(d, list) else d.get("tasks", [])
    except Exception:
        return []

def latest_completed(agent_id, issue_id):
    ts = agent_tasks(agent_id)
    completed = [t for t in ts if t.get("issue_id") == issue_id and t.get("status") == "completed"]
    completed.sort(key=lambda t: t.get("completed_at") or "", reverse=True)
    return completed[0] if completed else None

def is_accept_verdict(output: str) -> bool:
    if not output: return False
    out_upper = output.upper()
    if "ACCEPT" not in out_upper: return False
    if "REJECT" in out_upper: return False
    return True

# FIX-1: cppdev task completed + status in_progress -> in_review
def fix_status_in_review(fp, iid):
    iss = issue_get(iid)
    if not iss: return False
    if iss.get("status") != "in_progress":
        log(fp, f"  [FIX-1-SKIP] {iid[:8]} status={iss.get('status')} (not in_progress)")
        return False
    latest = latest_completed(CPPDEV, iid)
    if not latest:
        log(fp, f"  [FIX-1-SKIP] {iid[:8]} no cppdev completed task yet")
        return False
    log(fp, f"  [FIX-1] {iid[:8]} cppdev completed={latest.get('completed_at')[:19]} -> in_review", kind="FIX1")
    r = mc(["issue", "status", iid, "in_review", "--no-start"])
    return r.returncode == 0

# FIX-2: in_review + no verifier running/queued -> assign + rerun
def assign_verifier(fp, iid):
    iss = issue_get(iid)
    if not iss: return False
    if iss.get("status") != "in_review":
        log(fp, f"  [FIX-2-SKIP] {iid[:8]} status={iss.get('status')} (not in_review)")
        return False, "not in_review"
    if iss.get("assignee_id") == VERIFIER:
        log(fp, f"  [FIX-2-SKIP] {iid[:8]} already assigned to WVmpVerifier")
        return False, "already assigned"

    # FIX-2-SKIP dedup (v3.18.2): verifier task already running/queued?
    v_running = [t for t in agent_tasks(VERIFIER)
                 if t.get("issue_id") == iid and t.get("status") in ("running", "queued")]
    if v_running:
        log(fp, f"  [FIX-2-SKIP] {iid[:8]} verifier task already {v_running[0].get('status')}")
        return False, "verifier already running/queued"

    # Accept-history check (v3.18.2): already Accept?
    v_completed = [t for t in agent_tasks(VERIFIER)
                   if t.get("issue_id") == iid and t.get("status") == "completed"]
    if v_completed:
        v_completed.sort(key=lambda t: t.get("completed_at") or "", reverse=True)
        latest = v_completed[0]
        out = ((latest.get("result") or {}).get("output", "") or "")
        if is_accept_verdict(out):
            log(fp, f"  [FIX-2-SKIP] {iid[:8]} verifier already Accept, skip")
            return False, "verifier already Accept"

    # assign + rerun
    r = mc(["issue", "assign", iid, "--to-id", VERIFIER])
    if r.returncode != 0:
        log(fp, f"  [FIX-2-FAIL] {iid[:8]} assign failed rc={r.returncode}")
        return False, "assign failed"
    r = mc(["issue", "rerun", iid])
    if r.returncode != 0:
        log(fp, f"  [FIX-2-FAIL] {iid[:8]} rerun failed rc={r.returncode}")
        return False, "rerun failed"
    log(fp, f"  [FIX-2] {iid[:8]} assign WVmpVerifier + rerun OK", kind="FIX2")
    return True, "ok"

# FIX-3: verifier Accept -> done (with re-fire confirmation pattern, v3.18.2)
def fix_status_done(fp, iid):
    iss = issue_get(iid)
    if not iss: return False
    if iss.get("status") not in ("in_review", "in_progress"):
        log(fp, f"  [FIX-3-SKIP] {iid[:8]} status={iss.get('status')} (not in_review/in_progress)")
        return False
    latest = latest_completed(VERIFIER, iid)
    if not latest:
        log(fp, f"  [FIX-3-SKIP] {iid[:8]} no verifier completed task yet")
        return False
    out = ((latest.get("result") or {}).get("output", "") or "")
    # Mode 1: explicit verdict line
    verdict = None
    for line in out.split("\n"):
        L = line.upper()
        if (("POSTED" in L and "VERDICT" in L) or L.startswith("VERDICT:") or L.startswith("**VERDICT")):
            if "REJECT" in L: verdict = "Reject"; break
            if "ACCEPT" in L: verdict = "Accept"; break
    # Mode 2: re-fire confirmation (v3.18.2放宽)
    if verdict is None:
        out_upper = out.upper()
        if "PREVIOUS ACCEPT VERDICT" in out_upper:
            verdict = "Accept"
        elif "RE-VERIFIED" in out_upper and "ACCEPT" in out_upper:
            verdict = "Accept"
    if verdict != "Accept":
        log(fp, f"  [FIX-3-SKIP] {iid[:8]} verifier verdict={verdict} (not Accept)")
        return False
    log(fp, f"  [FIX-3] {iid[:8]} verifier Accept -> done (verdict at {latest.get('completed_at')[:19]})", kind="FIX3")
    r = mc(["issue", "status", iid, "done", "--no-start"])
    return r.returncode == 0

def main():
    with open(LOG_PATH, "a", encoding="utf-8") as fp:
        log(fp, f"=== WVmp watcher start (pid={os.getpid()}, interval={INTERVAL}s, log={LOG_PATH}) ===")
        log(fp, f"target issues: {[i[:8] for i in TARGET_ISSUE_IDS]}")
        log(fp, f"project={PROJECT[:8]}, cppdev={CPPDEV[:8]}, verifier={VERIFIER[:8]}")
        poll = 0
        while True:
            poll += 1
            log(fp, f"--- poll #{poll} ---")
            for iid in TARGET_ISSUE_IDS:
                iss = issue_get(iid)
                if not iss:
                    log(fp, f"  {iid[:8]}: issue_get returned None")
                    continue
                status = iss.get("status")
                assignee = iss.get("assignee_id")
                log(fp, f"  {iid[:8]} status={status} assignee={str(assignee)[:8]}")
                # Chain: todo -> in_progress (agent picks) -> in_progress (agent works) -> in_progress completed -> FIX-1
                if status == "in_progress" and assignee == CPPDEV:
                    fix_status_in_review(fp, iid)
                elif status == "in_progress" and assignee == VERIFIER:
                    # verifier works; wait
                    log(fp, f"  [WAIT] {iid[:8]} verifier in progress")
                elif status == "in_review":
                    if assignee == VERIFIER:
                        fix_status_done(fp, iid)
                    else:
                        assign_verifier(fp, iid)
                elif status == "done":
                    log(fp, f"  [DONE] {iid[:8]} already done")
                else:
                    log(fp, f"  [NOOP] {iid[:8]} status={status} assignee={str(assignee)[:8]}")
            log(fp, f"--- sleep {INTERVAL}s ---")
            time.sleep(INTERVAL)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("watcher stopped by user", flush=True)
        sys.exit(0)