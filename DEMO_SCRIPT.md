# Library Lending Blockchain Tracker — Demo Video Script

**Target runtime:** about 8–10 minutes  
**Recording style:** capture the running CLI full-screen; type one command at a
time and leave the result visible before continuing. The narration below is a
guide, not text that must be read word for word.

## Before recording

The application calculates lateness from the real system clock. It has no
command for advancing time, so a fresh loan cannot become overdue during a
short recording. You can record today: run the live walkthrough in an isolated
folder and insert the existing captured late-return screenshot as a clearly
labeled cutaway. Do not present that still image as live output.

1. Open PowerShell in the project folder. Create a new, empty demo folder. If
   the folder already exists, choose a different name rather than deleting or
   overwriting it. Keep the existing `screenshots` folder available for the
   late-return cutaway.

   ```powershell
   $DemoRoot = Join-Path $env:USERPROFILE 'Desktop\LibraryDemo'
   New-Item -ItemType Directory -Path $DemoRoot
   $env:PATH = 'C:\msys64\ucrt64\bin;' + $env:PATH
   & C:\msys64\ucrt64\bin\gcc.exe -std=c11 -Wall -Wextra -Wpedantic -O2 `
       -o (Join-Path $DemoRoot 'library_tracker.exe') .\src\main.c -lcrypto
   if ($LASTEXITCODE -ne 0) { throw 'Build failed; do not record yet.' }
   Copy-Item .\books.txt, .\copies.txt, .\members.txt, .\users.txt `
       -Destination $DemoRoot
   Set-Location $DemoRoot
   .\library_tracker.exe --model utxo --difficulty 2
   ```

   This builds from the current source and avoids the repository's stale
   `library_tracker.exe`, which depends on a legacy OpenSSL DLL. Keep this
   PowerShell window open so its UCRT64 runtime path is available when you run
   the executable.

2. Log in with `librarian` and `library2026`. Seed a loan that will be overdue
   only if you plan to record a follow-up after the due date; this is not
   needed for today's recording.

   ```text
   borrow BK003 ALU003 BK003-C01
   mine solo ALU003
   quit
   ```

3. For today's recording, start the application in the demo folder. Do not
   copy the repository's existing `blockchain.dat`, `library_state.dat`,
   token-state, or key files into it. The demo will create its own state. Keep
   the machine clock unchanged.

## Recorded walkthrough

### 0:00–0:40 — Introduction and setup

**Say:** “This is a local library lending application backed by a signed,
proof-of-work blockchain. I’ll show registration and copy-level inventory,
borrowing and reservations, token rewards and mining modes, fines, fraud
review, and chain integrity. Requests are queued first; mining confirms them.”

At the PowerShell prompt in the demo folder:

```powershell
.\library_tracker.exe --model utxo --difficulty 2
```

At the application prompts, enter:

```text
Username: librarian
Password: library2026
```

### 0:40–1:45 — Inventory, member/book registration, pending priority

**Say:** “The sample registry has members ALU001 through ALU003 and books
BK001 through BK003. I’m adding a member, a title, and two physical copies.
Copies are tracked individually, not just as a title-level count.”

Enter each line at the application prompt:

```text
difficulty_status
copies
register_member ALU004 Demo_Member CS1
register_book BK004 Demo_Title Demo_Author
add_copy BK004-C01 BK004 GOOD
add_copy BK004-C02 BK004 GOOD
copies
```

**Say:** “The startup overdue scan has identified the prepared BK003 loan. I’ll
put a normal borrow beside that overdue request, inspect the pending pool, and
mine the batch. The pool reports each request's priority; overdue work is
prioritized ahead of ordinary requests.”

```text
overdue BK003-C01
borrow BK001 ALU001 BK001-C01
pending
mine pool ALU001 ALU002
view
```

Pause on the pending output to show the priority and status fields. Pause on
the mining output to show the pool participants, attempts, contribution
shares, and confirmation.

### 1:45–2:30 — Invalid IDs and renewal

**Say:** “The CLI checks registry IDs before queuing a signed request. These
two attempts use an unknown book and an unknown member, so neither should
enter the pending pool.”

```text
borrow BK999 ALU001
borrow BK001 BAD001
```

**Say:** “Now I’ll renew ALU001’s confirmed loan. Renewal changes its due date
and, like other lending events, is queued until a block confirms it.”

```text
renew BK001-C01 ALU001
pending
mine solo ALU001
copy BK001-C01
```

Pause on the solo mining output to show difficulty, hash-attempt count, block
confirmation, and the resulting copy status.

### 2:30–3:10 — On-time return and token reward

**Say:** “This return is before the renewed due date. The application queues a
10-token gross reward; a one-token transaction fee means the member receives
9 net tokens after confirmation.”

```text
return BK001 ALU001 BK001-C01
balances
pending
mine solo ALU001
balances
```

Point out that the balance changes on confirmation, not when the return is
merely queued.

### 3:10–4:20 — Reservation and automatic offer on return

**Say:** “BK002 has two copies. I’ll borrow both so none are available, then
ALU003 can join its FIFO reservation queue.”

```text
borrow BK002 ALU001 BK002-C01
borrow BK002 ALU002 BK002-C02
pending
mine pool ALU001 ALU002
reserve BK002 ALU003
reservations
```

**Say:** “When ALU001 returns a copy, the application offers that exact copy
to the first waiting member instead of making it generally available.”

```text
return BK002 ALU001 BK002-C01
copy BK002-C01
reservations
borrow BK002 ALU003 BK002-C01
pending
mine pool ALU001 ALU002
copy BK002-C01
```

Pause on the return message showing the automatic offer to ALU003, and then
on the final copy view showing the confirmed borrower.

### 4:20–5:00 — Cloud mining

**Say:** “The new BK004 and ALU004 registrations are available immediately.
I’ll queue a borrow and run three cloud-mining rounds. Cloud mining is a
simulation: the output separates gross rewards, rental and maintenance
charges, and cumulative net earnings.”

```text
borrow BK004 ALU004 BK004-C01
pending
mine cloud 3 ALU001
balances
```

ALU001 is used as the payout member because mining costs are charged to that
member. At the documented rates, three rounds credit 6 gross coins and charge
9 coins total (2 rental plus 1 maintenance per round), for a net cost of 3.
Leave the actual multi-round summary visible.

### 5:00–6:10 — Overdue detection, late return, fine settlement

**Say:** “The application uses the system clock to detect overdue loans and
calculate one fine coin per late day. A fresh demo loan cannot become overdue
in a few minutes, so I won't pretend this new session has a live overdue
record. I’ll show the live scan, then cut to the project's previously captured
late-return output to demonstrate the actual late reward.”

```text
overdue
view_fines
```

Insert [screenshots/05_late_return.png](./screenshots/05_late_return.png) as a
full-screen still with a small on-screen label: **“Previously captured CLI
output — late return.”** Keep it visible long enough to read the confirmed
`RETURNED` record and reward `5` (net after fee `4`).

**Say:** “This captured application output shows a late return earning 5 gross
tokens, or 4 after the one-token fee. Fine settlement is a separate signed
`FINEPAID` event: when an overdue balance exists, `settle_fine MEMBER_ID
COPY_ID AMOUNT` queues it, and mining confirms payment. This fresh session has
no overdue balance to settle, so I’m describing that command rather than
showing a fabricated successful settlement.”

### 6:10–7:00 — Fraud flag and manual review

**Say:** “The detector flags a member who tries to borrow the same title again
within 24 hours of a confirmed return. I’ll make that repeat request, inspect
the review queue, and approve it explicitly.”

```text
borrow BK001 ALU001 BK001-C01
pending
fraud_review
```

Copy the full request ID shown by `fraud_review`, then enter:

```text
approve_suspicious FULL_REQUEST_ID
pending
mine pool ALU001 ALU002
```

Replace `FULL_REQUEST_ID` with the exact ID from the output. Point out that the
suspicious request waits for a decision and is only mined after approval.

### 7:00–8:00 — Chain validation and tamper detection

**Say:** “Each block links to the previous hash, commits to its signed records
through a Merkle root, and must meet the configured proof-of-work difficulty.
Validation checks the stored chain. The tamper command changes only a
temporary in-memory copy, so it demonstrates detection without damaging the
saved ledger.”

```text
validate
tamper
validate
view
quit
```

Pause on the tamper result showing `INVALID`, then on the final validation
showing the saved chain remains `VALID`.

**Say:** “That completes the workflow: registration, copy-level loans and
reservations, queued and confirmed transactions, multiple mining modes,
rewards and fines, manual fraud review, and blockchain integrity checks.”

## Recording checklist

- Keep the command prompt and application output readable; enlarge the
  terminal font and close unrelated windows before recording.
- Do not show private-key files or copy them into a public location.
- Leave each key output visible long enough to read: pending priorities,
  pool reward shares, solo hash attempts, cloud earnings, fine settlement,
  fraud review, and both validation results.
- Do not claim cloud mining is real external infrastructure; it is a
  multi-round simulation in this application.
- If any command reports an error, stop and correct the demo state rather
  than narrating the expected success output over it.
