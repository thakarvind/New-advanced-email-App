import app

print("=== _llm_client (no key) ===")
print(app._llm_client())
print()

print("=== _chat fallback (returns None silently) ===")
print(repr(app._chat("sys", "hello")))
print()

print("=== classify (no LLM -> heuristic fallback) ===")
result = app.classify("Recruiter Bob", "recruiter@example.com",
                      "Onsite interview next week?",
                      "Hi Alex, available next Tuesday?")
print(f"  priority={result[0]!r} intent={result[1]!r}")
print(f"  summary={result[2]!r}")
print(f"  draft={result[3]!r}")
assert result[0] == "needs_reply", "recruiter mail must classify as needs_reply"
assert result[1] == "recruiter"
nz = app.classify("Lenny's", "newsletter@substack.com", "Your weekly digest", "Issue 142")
assert nz[0] == "noise", f"newsletter must classify as noise, got {nz[0]!r}"
print("  OK: heuristic classify returns valid priorities")
print()

print("=== draft_reply (no LLM -> fallback template, known issue #11) ===")
print(repr(app.draft_reply("Jane Smith", "Quick question", "Can we sync Tuesday?")))
print()

print("=== draft_compose (no LLM -> fallback template) ===")
print(repr(app.draft_compose("team@acme.com", "Project kick-off", "intro the team")))
print()

print("=== _heuristic_priority ===")
for s in ["Invoice #123", "Onsite interview", "Weekly digest", "Random subject"]:
    p = app._heuristic_priority("x@example.com", s)
    print(f"  {s!r:30} -> {p}")
print()

print("=== _try_parse_json (bug 10 fix - bracket matching, not regex) ===")
print("  valid:", app._try_parse_json('blah {"priority":"fyi","intent":"x"} trailing'))
print("  nested:", app._try_parse_json('pre {"a":{"b":1},"c":2} post'))
print("  unbalanced:", app._try_parse_json('broken {but no close'))
print("  empty string:", app._try_parse_json(''))
braces_in_string = app._try_parse_json('{"x":"has } in it"}')
print("  braces-in-string:", braces_in_string)
assert braces_in_string == {"x": "has } in it"}
print()

print("=== folder_from_labels (PRISM/Snoozed -> snoozed) ===")
print("  ", app.folder_from_labels(["PRISM/Snoozed", "UNREAD"]))
assert app.folder_from_labels(["PRISM/Snoozed", "UNREAD"]) == ("snoozed", False, False)
assert app.folder_from_labels(["INBOX", "STARRED"]) == ("inbox", True, True)
assert app.folder_from_labels(["SENT"]) == ("sent", True, False)
print("  OK: snoozed/labels mapping")
print()

print("=== password hashing (pbkdf2 round-trip) ===")
h1 = app._hash_pw("hunter2!")
assert app._verify_pw("hunter2!", h1), "valid password must verify"
assert not app._verify_pw("wrong", h1), "wrong password must fail"
assert not app._verify_pw("hunter2!", "garbage"), "malformed hash must fail"
print("  OK: pbkdf2 hash round-trip")
print()

print("ALL FALLBACK CHECKS PASSED")
