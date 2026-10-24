"""Demo 3: pinned image check, no suspend, session isolation, wipe, orphan cleanup (requirements 3, 4, 13, 14, 16, 21, 24)."""
from datetime import datetime, timedelta, timezone

from azure.containerapps.sandbox import AutoDeletePolicy, AutoSuspendPolicy, LifecyclePolicy

from common import sandbox_group_client

APPROVED_DISK_ID = "b8782cab-82d3-4eaa-880d-24549076ea98"  # python-3.12-code-interpreter, approved by the security authority
group = sandbox_group_client("orchestrator")
created = []


def step(text: str) -> None:
    print(f"\n-- {text}", flush=True)


def new_session(name: str):
    sandbox = group.begin_create_sandbox(
        disk="python-3.12-code-interpreter", labels={"purpose": "contoso-demo", "session": name}
    ).result()
    created.append(sandbox)
    # No suspend means no memory or disk snapshot of the session; auto-delete bounds the lifetime
    sandbox.set_lifecycle_policy(
        LifecyclePolicy(
            auto_suspend=AutoSuspendPolicy(enabled=False),
            auto_delete=AutoDeletePolicy(enabled=True, delete_interval_seconds=900),
        )
    )
    return sandbox


def verify(sandbox, expected_disk_id: str) -> bool:
    info = sandbox.get()
    checks = {
        "disk image is the approved one": info.sources_ref.disk_image.id == expected_disk_id,
        "created from a disk, not a snapshot": info.sources_ref.snapshot is None,
        "egress default is Deny": info.egress_policy.default_action == "Deny",
        "no ports exposed": not info.ports,
        "suspend disabled": not info.lifecycle.auto_suspend.enabled,
        "auto-delete enabled": bool(info.lifecycle.auto_delete and info.lifecycle.auto_delete.enabled),
    }
    for name, ok in checks.items():
        print(f"   {'PASS' if ok else 'FAIL'}  {name}")
    return all(checks.values())


try:
    step("1. Create two sessions from the approved disk id, suspend off, auto-delete 15 min")
    a = new_session("a")
    a.set_egress_default("Deny")
    b = new_session("b")
    b.set_egress_default("Deny")
    print(f"session a = {a.sandbox_id}\nsession b = {b.sandbox_id}")

    step("2. Verify before releasing data (fail closed)")
    print("session a against the approved disk id:")
    assert verify(a, APPROVED_DISK_ID)
    print("session a against a different expected id (simulates an unapproved replacement):")
    print("   release data?", verify(a, "00000000-0000-0000-0000-000000000000"))

    step("3. Session isolation: a secret written in session a is not visible in session b")
    a.write_file("/tmp/secret.txt", "session-a-only")
    print("session a reads it ->", a.exec("cat /tmp/secret.txt").stdout)
    print("session b reads it ->", b.exec("cat /tmp/secret.txt 2>&1; echo exit=$?").stdout.strip())

    step("4. Wipe: delete session a, create a new session from the same disk, look for the old file")
    group.delete_sandbox(a.sandbox_id)
    c = new_session("c")
    print("new session sees old file ->", c.exec("ls /tmp/secret.txt 2>&1; echo exit=$?").stdout.strip())

    step("5. Orphan cleanup using only metadata (labels and age), no session keys or contents")
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=1)
    for s in group.list_sandboxes(labels={"purpose": "contoso-demo"}):
        age_ok = datetime.fromisoformat(s.created_at) < cutoff
        print(f"   {s.id} labels={s.labels} older than cutoff={age_ok}")
        if age_ok:
            group.delete_sandbox(s.id)
    left = list(group.list_sandboxes(labels={"purpose": "contoso-demo"}))
    print("sandboxes left after sweep:", len(left))
finally:
    for s in created:
        try:
            group.delete_sandbox(s.sandbox_id)
        except Exception:
            pass
