VulnLawyers - CTF Walkthrough

📁 Repository Overview

  This repository contains a full walkthrough of the VulnLawyers CTF, solved using only:

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

  ![Alt_text](https://github.com/0xDarkwaveSiren/Vulnlawyers_0xWalkthrough/blob/main/Screenshots/ffuf1.png?raw=true)

  ![Alt_text](https://github.com/0xDarkwaveSiren/Vulnlawyers_0xWalkthrough/blob/main/Screenshots/loginpage.png?raw=true)

🌐 3. Subdomain Discovery with ffuf (Main Domain)

  _ffuf -w subdomains.txt -u https://sufrin.ctfi/ -H "Host: FUZZ.sufrin.ctfi"_

  Key result:

    data

  ![Alt_text](https://github.com/0xDarkwaveSiren/Vulnlawyers_0xWalkthrough/blob/main/Screenshots/ffuf2.png?raw=true)

📂 4. Directory Fuzzing with ffuf (Subdomain: data)

  _ffuf -w subdomains.txt -u https://data.sufrin.ctfi/FUZZ_

  Key result:

    /users

  ![Alt_text](https://github.com/0xDarkwaveSiren/Vulnlawyers_0xWalkthrough/blob/main/Screenshots/ffuf3.png?raw=true)

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

  ![Alt_text](https://github.com/0xDarkwaveSiren/Vulnlawyers_0xWalkthrough/blob/main/Screenshots/users.png?raw=true)

  Intercepted GET _/login_

  Key finding:

    /lawyers-only

  ![Alt_text](https://github.com/0xDarkwaveSiren/Vulnlawyers_0xWalkthrough/blob/main/Screenshots/login.png?raw=true)

  ![Alt_text](https://github.com/0xDarkwaveSiren/Vulnlawyers_0xWalkthrough/blob/main/Screenshots/lawyers-onlypage.png?raw=true)

  Intercepted POST _/lawyers-only_ (login attempt)

  Key findings (Structure):

    email=admin&password=admin

  ![Alt_text](https://github.com/0xDarkwaveSiren/Vulnlawyers_0xWalkthrough/blob/main/Screenshots/lawyers-only-login-attempt.png?raw=true)

  ![Alt_text](https://github.com/0xDarkwaveSiren/Vulnlawyers_0xWalkthrough/blob/main/Screenshots/lawyers-only.png?raw=true)

🔑 6. Login Access with Caido

  Automated Matrix Payloads with Caido

  Used usernames found in _/users_ domain and _passwords.txt_ file provided by HackingHub

  Gained credentials and access to _/lawyers-only-profile_

  ![Alt_text](https://github.com/0xDarkwaveSiren/Vulnlawyers_0xWalkthrough/blob/main/Screenshots/loginaccess.png?raw=true)

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

🔓 8. Privilege Escalation 

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

  ![Alt_text](https://github.com/0xDarkwaveSiren/Vulnlawyers_0xWalkthrough/blob/main/Screenshots/lawyers-only-profile-details2.png?raw=true)

  Gained access as Shayne Cairns (Case Manger - Admin)

  ![Alt_text](https://github.com/0xDarkwaveSiren/Vulnlawyers_0xWalkthrough/blob/main/Screenshots/access-as-manager.png?raw=true)

  ![Alt_text](https://github.com/0xDarkwaveSiren/Vulnlawyers_0xWalkthrough/blob/main/Screenshots/deletedcase.png?raw=true)

🏁 7. Flags Captured

Flag # 1

  Path: _https://data.sufrin.ctfi/

    [^FLAG^E78DEBBFDFBEAFF1336B599B0724A530^FLAG^]

  ![Alt_text](https://github.com/0xDarkwaveSiren/Vulnlawyers_0xWalkthrough/blob/main/Screenshots/data.png?raw=true)

Flag # 2

  Path: _https://sufrin.ctfi/users_

    [^FLAG^25032EB0D322F7330182507FBAA1A55F^FLAG^]

  ![Alt_text](https://github.com/0xDarkwaveSiren/Vulnlawyers_0xWalkthrough/blob/main/Screenshots/users.png?raw=true)

Flag # 3

  Caido Intercept: GET _login_

    [^FLAG^FB52470E40F47559EBA87252B2D4CF67^FLAG^]

  ![Alt_text](https://github.com/0xDarkwaveSiren/Vulnlawyers_0xWalkthrough/blob/main/Screenshots/login.png?raw=true)

Flag # 4

  Staff Portal: _https://sufrin.ctfi/lawyers-only_

    [^FLAG^7F1ED1F306FC4E3399CEE15DF4B0AE3C^FLAG^]

  ![Alt_text](https://github.com/0xDarkwaveSiren/Vulnlawyers_0xWalkthrough/blob/main/Screenshots/loginaccess.png?raw=true)

Flag # 5

  Caido Request Replay: GET _/lawyers-only-profile-details/2_

    [^FLAG^938F5DC109A1E9B4FF3E3E92D29A56B3^FLAG^]

  ![Alt_text](https://github.com/0xDarkwaveSiren/Vulnlawyers_0xWalkthrough/blob/main/Screenshots/lawyers-only-profile-details2.png?raw=true)
  
Flag # 6

  Staff Portal as Shayne Cairns and deleted current case.

    [^FLAG^B38BAE0B8B804FCB85C730F10B3B5CB5^FLAG^]

  ![Alt_text](https://github.com/0xDarkwaveSiren/Vulnlawyers_0xWalkthrough/blob/main/Screenshots/deletedcase.png?raw=true)

📌 Lessons Learned

Efficient use of just 2 tools (ffuf, caido) is enough to fully compromise a box

Importance of analyzing requests carefully in Caido

Logic flaws and poorly implemented login mechanisms are often more exploitable than buffer overflows
