# VulnLawyers - Complete CTF Walkthrough

> **Professional penetration testing methodology demonstration** using minimalist tooling (ffuf + Caido) to achieve full system compromise through web application vulnerabilities.

[![CTF Platform](https://img.shields.io/badge/Platform-HackingHub-red)](https://hackinghub.io)
[![Tools Used](https://img.shields.io/badge/Tools-ffuf%20%7C%20Caido-blue)](https://github.com)
[![Difficulty](https://img.shields.io/badge/Difficulty-Intermediate-orange)](https://github.com)
[![Status](https://img.shields.io/badge/Status-Complete-success)](https://github.com)
[![Flags Captured](https://img.shields.io/badge/Flags-6%2F6-brightgreen)](https://github.com)

---

## 📋 Table of Contents

- [Overview](#overview)
- [Methodology](#methodology)
- [Tools Used](#tools-used)
- [Target Information](#target-information)
- [Walkthrough](#walkthrough)
  - [1. Reconnaissance](#1-reconnaissance)
  - [2. Directory Enumeration](#2-directory-enumeration)
  - [3. Subdomain Discovery](#3-subdomain-discovery)
  - [4. Information Disclosure](#4-information-disclosure)
  - [5. Authentication Analysis](#5-authentication-analysis)
  - [6. Credential Attack](#6-credential-attack)
  - [7. Privilege Escalation via IDOR](#7-privilege-escalation-via-idor)
  - [8. Administrative Access](#8-administrative-access)
- [Flags Captured](#flags-captured)
- [Key Vulnerabilities](#key-vulnerabilities)
- [Lessons Learned](#lessons-learned)
- [Remediation Recommendations](#remediation-recommendations)

---

## 🎯 Overview

This repository documents a complete penetration test of the **VulnLawyers** web application from HackingHub CTF. The engagement demonstrates a minimalist approach to web application security assessment, achieving full compromise using only two primary tools: **ffuf** for enumeration and **Caido** for request analysis and exploitation.

**Key Achievement:** 6/6 flags captured through systematic enumeration, authentication bypass, and privilege escalation via IDOR vulnerability.

**Notable Approach:** Proof that sophisticated exploitation doesn't require extensive tooling - understanding web application logic and careful analysis are often more valuable than automated scanners.

---

## 🔍 Methodology

This walkthrough follows a structured penetration testing approach:

1. **Reconnaissance** - Initial target assessment
2. **Enumeration** - Directory and subdomain discovery
3. **Analysis** - Request/response inspection and logic flaw identification
4. **Exploitation** - Credential attacks and authentication bypass
5. **Privilege Escalation** - IDOR exploitation for administrative access
6. **Post-Exploitation** - Data exfiltration and proof of compromise

**Philosophy:** Work smarter, not harder. Two well-understood tools can be more effective than a dozen automated scanners when you understand the underlying logic.

---

## 🛠️ Tools Used

### Primary Tools

**[ffuf](https://github.com/ffuf/ffuf)** - Fast Web Fuzzer
- Directory enumeration
- Subdomain discovery
- Lightweight and efficient

**[Caido](https://caido.io/)** - Modern Web Proxy
- Request/response interception
- Automated payload attacks (Matrix)
- Request replay for IDOR testing

### Environment
- **OS:** Parrot Security OS
- **Wordlists:** Custom subdomain list, HackingHub-provided password list

---

## 🖥️ Target Information

**Target URL:** `https://sufrin.ctfi/`

**Scope:** Web application assessment of VulnLawyers law firm platform

**Initial Access:** Public-facing website, no credentials provided

**Objective:** Enumerate vulnerabilities, gain unauthorized access, escalate privileges, capture all flags

**Note:** No open ports were discovered during initial reconnaissance; assessment focused entirely on web application layer.

---

## 📖 Walkthrough

### 🛰️ 1. Reconnaissance

**Initial Assessment:**
- Target accessible via HTTPS
- Standard web application
- No additional open ports discovered

**Decision:** Proceed with web-based enumeration using known entry point.

---

### 📂 2. Directory Enumeration

**Tool:** ffuf  
**Command:**
```bash
ffuf -w subdomains.txt -u https://sufrin.ctfi/FUZZ
```

**Key Discoveries:**
- `/css` - Static resources
- `/images` - Image directory
- `/login` - Authentication endpoint ⭐

![Directory Fuzzing Results](https://github.com/0xDarkwaveSiren/Vulnlawyers_0xWalkthrough/blob/main/Screenshots/ffuf1.png?raw=true)

![Login Page Discovery](https://github.com/0xDarkwaveSiren/Vulnlawyers_0xWalkthrough/blob/main/Screenshots/loginpage.png?raw=true)

**Analysis:** Standard web application structure with authentication mechanism identified as primary target.

---

### 🌐 3. Subdomain Discovery

**Tool:** ffuf  
**Command:**
```bash
ffuf -w subdomains.txt -u https://sufrin.ctfi/ -H "Host: FUZZ.sufrin.ctfi"
```

**Key Discovery:**
- `data.sufrin.ctfi` - Subdomain hosting additional resources ⭐

![Subdomain Discovery](https://github.com/0xDarkwaveSiren/Vulnlawyers_0xWalkthrough/blob/main/Screenshots/ffuf2.png?raw=true)

**Significance:** Identified secondary attack surface for further enumeration.

---

### 📂 4. Subdomain Enumeration (data.sufrin.ctfi)

**Tool:** ffuf  
**Command:**
```bash
ffuf -w subdomains.txt -u https://data.sufrin.ctfi/FUZZ
```

**Key Discovery:**
- `/users` - User information endpoint ⭐

![Subdomain Directory Fuzzing](https://github.com/0xDarkwaveSiren/Vulnlawyers_0xWalkthrough/blob/main/Screenshots/ffuf3.png?raw=true)

**Impact:** Potential information disclosure vulnerability identified.

---

### 🔐 5. Information Disclosure via /users Endpoint

**Tool:** Caido  
**Request:** `GET /users`

**Response:**
```json
{
  "users": [
    {
      "name": "Yusef Mcclain",
      "email": "[REDACTED]"
    },
    {
      "name": "Shayne Cairns",
      "email": "[REDACTED]"
    },
    {
      "name": "Eisa Evans",
      "email": "[REDACTED]"
    },
    {
      "name": "Jaskaran Lowe",
      "email": "[REDACTED]"
    },
    {
      "name": "Marsha Blankenship",
      "email": "[REDACTED]"
    }
  ],
  "flag": "[FLAG CAPTURED - See Flags Section]"
}
```

![Users Endpoint Response](https://github.com/0xDarkwaveSiren/Vulnlawyers_0xWalkthrough/blob/main/Screenshots/users.png?raw=true)

**Vulnerability:** Information Disclosure  
**Impact:** Valid usernames and email addresses exposed, flag captured

---

### 🔑 6. Authentication Analysis

**Tool:** Caido

**Phase 1: Login Page Analysis**

Intercepted `GET /login` - Discovered hidden endpoint:
- `/lawyers-only` - Staff portal ⭐

![Login Interception](https://github.com/0xDarkwaveSiren/Vulnlawyers_0xWalkthrough/blob/main/Screenshots/login.png?raw=true)

![Lawyers-Only Portal](https://github.com/0xDarkwaveSiren/Vulnlawyers_0xWalkthrough/blob/main/Screenshots/lawyers-onlypage.png?raw=true)

**Phase 2: Authentication Mechanism Analysis**

Intercepted `POST /lawyers-only` (login attempt)

**Request Structure:**
```
POST /lawyers-only
Content-Type: application/x-www-form-urlencoded

email=admin&password=admin
```

![Login POST Request](https://github.com/0xDarkwaveSiren/Vulnlawyers_0xWalkthrough/blob/main/Screenshots/lawyers-only-login-attempt.png?raw=true)

![Login Response](https://github.com/0xDarkwaveSiren/Vulnlawyers_0xWalkthrough/blob/main/Screenshots/lawyers-only.png?raw=true)

**Analysis:** Simple POST-based authentication using email/password parameters.

---

### 🎯 7. Credential Attack (Automated with Caido)

**Technique:** Matrix Payloads (Credential Stuffing)

**Attack Configuration:**
- **Usernames:** Email addresses from `/users` endpoint
- **Passwords:** Password list provided by HackingHub
- **Tool:** Caido automated matrix attack

**Result:** ✅ Valid credentials discovered

**Access Gained:** 
- Portal: `/lawyers-only-profile`
- User level: Standard attorney access

![Successful Authentication](https://github.com/0xDarkwaveSiren/Vulnlawyers_0xWalkthrough/blob/main/Screenshots/loginaccess.png?raw=true)

**Vulnerability:** Weak Password Policy + No Account Lockout

---

### 🔓 8. Privilege Escalation via IDOR

**Vulnerability Type:** Insecure Direct Object Reference (IDOR)

**Discovery:**

Intercepted `GET /lawyers-only-profile-details/4` (current user)

**Response:**
```json
{
  "id": 4,
  "name": "[REDACTED]",
  "email": "[REDACTED]",
  "password": "[REDACTED]"
}
```

**Hypothesis:** User ID parameter might be manipulable to access other user profiles.

**Exploitation:**

Modified request: `GET /lawyers-only-profile-details/2`

**Response:**
```json
{
  "id": 2,
  "name": "Shayne Cairns",
  "email": "[REDACTED]",
  "password": "[REDACTED]",
  "flag": "[FLAG CAPTURED - See Flags Section]"
}
```

![IDOR Exploitation](https://github.com/0xDarkwaveSiren/Vulnlawyers_0xWalkthrough/blob/main/Screenshots/lawyers-only-profile-details2.png?raw=true)

**Critical Finding:** Shayne Cairns identified as **Case Manager** (Administrator role)

**Impact:** Administrative credentials compromised through IDOR vulnerability.

---

### 👑 9. Administrative Access & Impact

**Authenticated As:** Shayne Cairns (Case Manager - Admin)

![Admin Portal Access](https://github.com/0xDarkwaveSiren/Vulnlawyers_0xWalkthrough/blob/main/Screenshots/access-as-manager.png?raw=true)

**Administrative Capabilities:**
- Full access to case management system
- Ability to modify/delete cases
- Access to all user information
- System-wide privileges

**Proof of Compromise:**
Successfully deleted active case, demonstrating full administrative control.

![Case Deletion Proof](https://github.com/0xDarkwaveSiren/Vulnlawyers_0xWalkthrough/blob/main/Screenshots/deletedcase.png?raw=true)

**Attack Chain Summary:**
```
Public Access 
  → Directory Enumeration 
    → Information Disclosure (/users)
      → Credential Attack (weak passwords)
        → Standard User Access
          → IDOR Exploitation
            → Administrative Access
              → Full System Compromise
```

---

## 🏁 Flags Captured

### Flag #1: Subdomain Discovery
**Location:** `https://data.sufrin.ctfi/`  
**Flag:** `^FLAG^E78DEBBFDFBEAFF1336B599B0724A530^FLAG^`  
**Method:** Subdomain enumeration with ffuf

![Flag 1](https://github.com/0xDarkwaveSiren/Vulnlawyers_0xWalkthrough/blob/main/Screenshots/data.png?raw=true)

---

### Flag #2: Information Disclosure
**Location:** `https://sufrin.ctfi/users`  
**Flag:** `^FLAG^25032EB0D322F7330182507FBAA1A55F^FLAG^`  
**Method:** Accessing exposed user data endpoint

![Flag 2](https://github.com/0xDarkwaveSiren/Vulnlawyers_0xWalkthrough/blob/main/Screenshots/users.png?raw=true)

---

### Flag #3: Hidden Endpoint Discovery
**Location:** Caido intercept of `GET /login`  
**Flag:** `^FLAG^FB52470E40F47559EBA87252B2D4CF67^FLAG^`  
**Method:** Request interception revealing `/lawyers-only` endpoint

![Flag 3](https://github.com/0xDarkwaveSiren/Vulnlawyers_0xWalkthrough/blob/main/Screenshots/login.png?raw=true)

---

### Flag #4: Authentication Bypass
**Location:** `https://sufrin.ctfi/lawyers-only` (Staff Portal)  
**Flag:** `^FLAG^7F1ED1F306FC4E3399CEE15DF4B0AE3C^FLAG^`  
**Method:** Successful credential attack using matrix payloads

![Flag 4](https://github.com/0xDarkwaveSiren/Vulnlawyers_0xWalkthrough/blob/main/Screenshots/loginaccess.png?raw=true)

---

### Flag #5: IDOR Exploitation
**Location:** `GET /lawyers-only-profile-details/2`  
**Flag:** `^FLAG^938F5DC109A1E9B4FF3E3E92D29A56B3^FLAG^`  
**Method:** IDOR vulnerability exploitation via request replay

![Flag 5](https://github.com/0xDarkwaveSiren/Vulnlawyers_0xWalkthrough/blob/main/Screenshots/lawyers-only-profile-details2.png?raw=true)

---

### Flag #6: Administrative Privilege
**Location:** Staff Portal as Shayne Cairns (after case deletion)  
**Flag:** `^FLAG^B38BAE0B8B804FCB85C730F10B3B5CB5^FLAG^`  
**Method:** Proof of administrative access through destructive action

![Flag 6](https://github.com/0xDarkwaveSiren/Vulnlawyers_0xWalkthrough/blob/main/Screenshots/deletedcase.png?raw=true)

---

## 🚨 Key Vulnerabilities Identified

| Vulnerability | Severity | CWE | Impact |
|--------------|----------|-----|--------|
| Information Disclosure (/users) | HIGH | CWE-200 | User enumeration, credential attack preparation |
| Weak Password Policy | HIGH | CWE-521 | Successful credential stuffing attack |
| No Account Lockout | MEDIUM | CWE-307 | Enables automated credential attacks |
| Insecure Direct Object Reference (IDOR) | CRITICAL | CWE-639 | Privilege escalation to administrative access |
| Insufficient Access Controls | CRITICAL | CWE-284 | Full system compromise |
| Exposed Administrative Functions | HIGH | CWE-425 | Data manipulation and deletion |

---

## 💡 Lessons Learned

### Technical Insights

**1. Minimalist Tooling Can Be Highly Effective**
- Only two tools (ffuf + Caido) were needed for complete compromise
- Understanding tool capabilities deeply > having many tools
- Simple, focused approach often finds what automated scanners miss

**2. Logic Flaws Are Everywhere**
- IDOR vulnerabilities are still prevalent in modern applications
- Authentication mechanisms often have business logic flaws
- Manual testing reveals issues that automated tools overlook

**3. Information Disclosure Enables Attack Chains**
- The `/users` endpoint exposure was critical to the entire attack
- Small information leaks can cascade into major compromises
- Seemingly harmless data can be weaponized

**4. Sequential Enumeration Is Powerful**
- Systematic directory/subdomain enumeration reveals hidden attack surface
- Each discovery builds on the previous one
- Patience and thoroughness pay off

### Methodology Insights

**What Worked:**
- Systematic enumeration before exploitation
- Careful analysis of each request/response
- Understanding the application's intended logic
- Request replay for IDOR testing

**Developer Mindset Advantage:**
As someone who builds web applications, I could anticipate:
- How the API likely handled user IDs
- Where sensitive data might be exposed
- Common authentication implementation mistakes
- How the frontend/backend interaction worked

This "builder who breaks" perspective made exploitation more intuitive than purely offensive security approaches.

---

## 🛡️ Remediation Recommendations

### Critical Fixes (Implement Immediately)

**1. Fix IDOR Vulnerability**
```python
# BAD: Direct ID-based access
user = db.query(User).filter(User.id == request.params['id']).first()

# GOOD: Verify ownership before access
user = db.query(User).filter(
    User.id == request.params['id'],
    User.id == current_user.id  # or check permissions
).first()

if not user:
    return 403  # Forbidden
```

**2. Implement Proper Access Controls**
- Enforce authentication on all sensitive endpoints
- Implement role-based access control (RBAC)
- Verify user permissions before each action
- Never trust client-supplied IDs without validation

**3. Restrict Information Disclosure**
```python
# BAD: Exposing full user list
return jsonify(users=User.query.all())

# GOOD: Authenticated access only, limited fields
@require_auth
def get_users():
    return jsonify([{
        'name': u.name,
        # Don't expose emails, IDs, or other sensitive data
    } for u in User.query.filter_by(company=current_user.company)])
```

### High Priority

**4. Implement Account Lockout**
- Lock accounts after 5 failed login attempts
- Implement rate limiting on authentication endpoints
- Add CAPTCHA after failed attempts
- Log all authentication failures

**5. Strengthen Password Policy**
- Enforce minimum password complexity
- Implement password strength requirements
- Require regular password changes
- Check against common password lists

**6. Hide Administrative Endpoints**
- Don't expose admin URLs in client-side code
- Implement separate authentication for admin functions
- Use non-guessable admin paths
- Implement additional verification for destructive actions

### Medium Priority

**7. Security Headers**
```
Strict-Transport-Security: max-age=31536000
X-Frame-Options: DENY
Content-Security-Policy: default-src 'self'
X-Content-Type-Options: nosniff
```

**8. Comprehensive Logging**
- Log all authentication attempts
- Log privilege escalation attempts
- Log administrative actions
- Implement alerting for suspicious activity

---

## 📚 References & Resources

**Tools Used:**
- [ffuf - Fast Web Fuzzer](https://github.com/ffuf/ffuf)
- [Caido - Modern Web Security Toolkit](https://caido.io/)

**Vulnerability References:**
- [CWE-639: Insecure Direct Object Reference](https://cwe.mitre.org/data/definitions/639.html)
- [OWASP Top 10 - Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [OWASP Testing Guide - IDOR](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References)

**Learning Resources:**
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackTheBox](https://www.hackthebox.com/)
- [TryHackMe](https://tryhackme.com/)

---

## ⚖️ Legal & Ethical Disclaimer

**Important Notice:**

This walkthrough documents security testing performed in a legal, authorized Capture The Flag (CTF) environment provided by HackingHub. All activities were conducted:

- ✅ With explicit permission on designated vulnerable systems
- ✅ Within the scope of an authorized CTF competition
- ✅ For educational and skill development purposes
- ✅ Following responsible disclosure and ethical hacking principles

**⚠️ Warning:**

Unauthorized access to computer systems is illegal in most jurisdictions. The techniques documented here should **ONLY** be used:
- In authorized penetration testing engagements with written permission
- In designated CTF/training environments
- On systems you own or have explicit permission to test

**I do not condone or support:**
- Unauthorized access to systems
- Malicious hacking activities
- Privacy violations
- Any illegal use of these techniques

This content is provided for educational purposes only. Users are responsible for ensuring they have proper authorization before performing any security testing.

---

## 🎓 About This Walkthrough

This CTF solution is part of my journey learning offensive security and penetration testing. I document my CTF walkthroughs to:

- **Reinforce Learning:** Teaching is the best way to master a concept
- **Build Portfolio:** Demonstrate methodology and technical thinking
- **Help Others:** Share knowledge with the security community
- **Show Progression:** Document my growth from developer to security professional

**Author:** Andrea (@0xDarkwaveSiren)  
**Date Completed:** [Date]  
**Platform:** HackingHub CTF  
**Tools:** ffuf, Caido, Linux shell

**Background:** Full-stack developer transitioning to penetration testing. My development experience helps me understand application logic, which makes finding and exploiting vulnerabilities more intuitive. I approach security research with both a builder's and a breaker's mindset.

---

## 🤝 Feedback & Discussion

Found this walkthrough helpful? Have questions or alternative solutions?

- ⭐ **Star this repository** if you found it useful
- 🐛 **Open an issue** if you find errors or have questions
- 💬 **Discussions welcome** - I'm always learning and improving

**Connect:**
- GitHub: [@0xDarkwaveSiren](https://github.com/0xDarkwaveSiren)
- More CTF writeups and security projects on my profile

---

**"Understanding how things break makes you better at building them secure."** 🔱

*This walkthrough demonstrates that effective penetration testing isn't about the quantity of tools, but the quality of analysis. Two tools, careful methodology, and understanding of web application logic were sufficient for complete system compromise.*

---

## 🎯 Key Takeaways

1. **Minimalism Works:** 2 tools > 20 tools when used effectively
2. **Logic Flaws Matter:** IDOR still critical in 2024
3. **Information Leaks Cascade:** Small disclosures enable big attacks
4. **Developer Knowledge Helps:** Understanding how apps are built helps break them
5. **Methodology > Tools:** Systematic approach beats random exploitation

---

**#CTF #PenetrationTesting #WebSecurity #IDOR #ffuf #Caido #EthicalHacking**
