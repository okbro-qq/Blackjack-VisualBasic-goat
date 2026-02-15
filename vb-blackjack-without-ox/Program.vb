Imports System
Imports System.Collections.Generic
Imports System.IO
Imports System.Net
Imports System.Net.Http
Imports System.Text
Imports System.Text.RegularExpressions
Imports System.Threading.Tasks
Imports System.Web

Module Program
    Private listener As HttpListener
    Private serverUrl As String = "http://localhost:3000/"
    Private chatMessages As New List(Of ChatMessage)()
    Private users As New List(Of User)()
    Private httpClient As New HttpClient()
    
    ' Game statistics
    Private totalHandsDealt As Integer = 0
    Private playerWins As Integer = 0
    Private dealerWins As Integer = 0
    Private pushes As Integer = 0
    
    Class ChatMessage
        Public Property Name As String
        Public Property Content As String
        Public Property Timestamp As DateTime
    End Class
    
    Class User
        Public Property Username As String
        Public Property Password As String
        Public Property Role As String
    End Class
    
    Sub Main()
        Console.WriteLine("=== Blackjack Table Server ===")
        Console.WriteLine()
        
        ' Create a default dealer account for testing
        users.Add(New User With {
            .Username = "dealer",
            .Password = "dealer123",
            .Role = "dealer"
        })
        Console.WriteLine("Test dealer account created: username='dealer', password='dealer123'")
        Console.WriteLine()
        
        ' Initialize HttpListener
        listener = New HttpListener()
        listener.Prefixes.Add(serverUrl)
        
        Try
            listener.Start()
            Console.WriteLine($"Server running at {serverUrl}")
            Console.WriteLine("Press Ctrl+C to stop...")
            Console.WriteLine()
            
            ' Handle requests in a loop
            While True
                Dim context = listener.GetContext()
                HandleRequest(context)
            End While
        Catch ex As Exception
            Console.WriteLine($"Error: {ex.Message}")
        Finally
            listener.Stop()
        End Try
    End Sub
    
    Sub HandleRequest(context As HttpListenerContext)
        Dim request = context.Request
        Dim response = context.Response
        Dim path = request.Url.AbsolutePath
        
        Console.WriteLine($"{request.HttpMethod} {path}")
        
        Try
            ' Background proxy route
            If path = "/background/proxy" Then
                HandleBackgroundProxy(request, response)
            ' Background page route
            ElseIf path = "/background" Then
                ServeBackgroundPage(response)
            ' Auth routes
            ElseIf path = "/signup" And request.HttpMethod = "POST" Then
                HandleSignup(request, response)
            ElseIf path = "/login" And request.HttpMethod = "POST" Then
                HandleLogin(request, response)
            ElseIf path = "/auth" Then
                ServeAuthPage(response)
            ' Dashboard route
            ElseIf path = "/dashboard" Then
                ServeDashboardPage(request, response)
            ' Chat history route
            ElseIf path = "/chat/history" Then
                ServeChatHistory(response)
            ' Chat POST route
            ElseIf path = "/chat" And request.HttpMethod = "POST" Then
                HandleChatPost(request, response)
            ' Chat page route
            ElseIf path = "/chat" Then
                ServeChatPage(response)
            ' Navigate redirect handler
            ElseIf path = "/navigate" Then
                Dim urlParam = request.QueryString("url")
                If Not String.IsNullOrEmpty(urlParam) Then
                    response.StatusCode = 302
                    response.RedirectLocation = urlParam
                    response.Close()
                Else
                    SendResponse(response, "Missing url parameter", 400)
                End If
            ' Settings load config route
            ElseIf path = "/settings/load" Then
                Dim configName = request.QueryString("config")
                If Not String.IsNullOrEmpty(configName) Then
                    Dim configPath = $"configs/{configName}.json"
                    If File.Exists(configPath) Then
                        Dim jsonContent = File.ReadAllText(configPath)
                        Dim buffer = Encoding.UTF8.GetBytes(jsonContent)
                        response.ContentType = "application/json"
                        response.ContentLength64 = buffer.Length
                        response.StatusCode = 200
                        response.OutputStream.Write(buffer, 0, buffer.Length)
                        response.OutputStream.Close()
                    Else
                        SendResponse(response, $"Config '{configName}' not found", 404)
                    End If
                Else
                    SendResponse(response, "Missing config parameter", 400)
                End If
            ' Settings page route
            ElseIf path = "/settings" Then
                ServeStaticFile(response, "wwwroot/settings.html", "text/html")
            ' Game stats API route
            ElseIf path = "/game/record" And request.HttpMethod = "POST" Then
                HandleGameRecord(request, response)
            ' Game route
            ElseIf path = "/game" Then
                ServeStaticFile(response, "wwwroot/game.html", "text/html")
            ' Root route
            ElseIf path = "/" Or path = "/index.html" Then
                ServeLobbyPage(request, response)
            ' Static files
            ElseIf path.StartsWith("/") Then
                Dim filePath = "wwwroot" & path
                If File.Exists(filePath) Then
                    Dim contentType = GetContentType(filePath)
                    ServeStaticFile(response, filePath, contentType)
                Else
                    SendResponse(response, "404 Not Found", 404)
                End If
            Else
                SendResponse(response, "Blackjack Table demo is running", 200)
            End If
        Catch ex As Exception
            Console.WriteLine($"Error handling request: {ex.Message}")
            SendResponse(response, "Internal Server Error", 500)
        End Try
    End Sub
    
    Sub ServeStaticFile(response As HttpListenerResponse, filePath As String, contentType As String)
        If File.Exists(filePath) Then
            Dim content = File.ReadAllBytes(filePath)
            response.ContentType = contentType
            response.ContentLength64 = content.Length
            response.StatusCode = 200
            response.OutputStream.Write(content, 0, content.Length)
            response.OutputStream.Close()
        Else
            SendResponse(response, "File not found", 404)
        End If
    End Sub
    
    Sub SendResponse(response As HttpListenerResponse, message As String, statusCode As Integer)
        Dim buffer = Encoding.UTF8.GetBytes(message)
        response.ContentType = "text/plain"
        response.ContentLength64 = buffer.Length
        response.StatusCode = statusCode
        response.OutputStream.Write(buffer, 0, buffer.Length)
        response.OutputStream.Close()
    End Sub
    
    Function GetContentType(filePath As String) As String
        Dim extension = Path.GetExtension(filePath).ToLower()
        Select Case extension
            Case ".html", ".htm"
                Return "text/html"
            Case ".css"
                Return "text/css"
            Case ".js"
                Return "application/javascript"
            Case ".json"
                Return "application/json"
            Case ".png"
                Return "image/png"
            Case ".jpg", ".jpeg"
                Return "image/jpeg"
            Case ".gif"
                Return "image/gif"
            Case ".svg"
                Return "image/svg+xml"
            Case Else
                Return "application/octet-stream"
        End Select
    End Function
    
    Sub ServeChatPage(response As HttpListenerResponse)
        Dim html As String = "<!DOCTYPE html>
<html lang=""en"">
<head>
    <meta charset=""UTF-8"">
    <meta name=""viewport"" content=""width=device-width, initial-scale=1.0"">
    <title>Table Chat</title>
    <link rel=""stylesheet"" href=""/styles.css"">
    <style>
        .back-link { display: inline-block; color: #ffd700; text-decoration: none; font-size: 1rem; margin-top: 0.5rem; transition: opacity 0.3s; }
        .back-link:hover { opacity: 0.8; }
        .chat-board { background: rgba(255, 255, 255, 0.1); backdrop-filter: blur(10px); border-radius: 20px; padding: 2rem; box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2); border: 1px solid rgba(255, 255, 255, 0.18); max-width: 800px; margin: 0 auto; }
        .chat-form { margin-bottom: 2rem; }
        .form-group { margin-bottom: 1rem; }
        .form-label { display: block; font-size: 1rem; font-weight: 600; margin-bottom: 0.5rem; color: #ffd700; }
        .form-input, .form-textarea { width: 100%; padding: 0.8rem; font-size: 1rem; border: 2px solid rgba(255, 255, 255, 0.3); border-radius: 10px; background: rgba(255, 255, 255, 0.1); color: white; outline: none; transition: all 0.3s; font-family: inherit; }
        .form-input:focus, .form-textarea:focus { border-color: #ffd700; background: rgba(255, 255, 255, 0.15); }
        .form-textarea { min-height: 100px; resize: vertical; }
        .send-btn { padding: 1rem 2rem; font-size: 1rem; font-weight: 600; border: 2px solid #ffd700; border-radius: 10px; background: linear-gradient(135deg, #ffd700 0%, #ffed4e 100%); color: #1e3c72; cursor: pointer; transition: all 0.3s ease; width: 100%; }
        .send-btn:hover { background: linear-gradient(135deg, #ffed4e 0%, #ffd700 100%); transform: translateY(-2px); box-shadow: 0 6px 20px rgba(255, 215, 0, 0.4); }
        .chat-messages { margin-top: 2rem; padding-top: 2rem; border-top: 2px solid rgba(255, 255, 255, 0.2); max-height: 500px; overflow-y: auto; }
        .message { background: rgba(0, 0, 0, 0.3); border-radius: 10px; padding: 1rem; margin-bottom: 1rem; }
        .message-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; }
        .message-name { font-weight: 600; color: #ffd700; }
        .message-time { font-size: 0.8rem; opacity: 0.7; }
        .message-content { line-height: 1.5; }
        .message-content a { color: #4fc3f7; text-decoration: underline; }
        .hint { font-size: 0.85rem; opacity: 0.7; margin-top: 0.25rem; }
    </style>
</head>
<body>
    <div class=""container"">
        <header>
            <h1>💬 Table Chat</h1>
            <a href=""/navigate?url=/"" class=""back-link"">← Back to Lobby</a>
        </header>
        <main>
            <div class=""chat-board"">
                <form class=""chat-form"" id=""chat-form"">
                    <div class=""form-group"">
                        <label class=""form-label"" for=""name"">Display Name</label>
                        <input type=""text"" id=""name"" class=""form-input"" placeholder=""Your name"" required />
                    </div>
                    <div class=""form-group"">
                        <label class=""form-label"" for=""message"">Message</label>
                        <textarea id=""message"" class=""form-textarea"" placeholder=""Type your message..."" required></textarea>
                        <div class=""hint"">Use **bold**, *italic*, or [link](url) for formatting</div>
                    </div>
                    <button type=""submit"" class=""send-btn"">Send Message</button>
                </form>
                <div class=""chat-messages"" id=""chat-messages""></div>
            </div>
        </main>
    </div>
    <script>
        const form = document.getElementById('chat-form');
        const nameInput = document.getElementById('name');
        const messageInput = document.getElementById('message');
        const messagesDiv = document.getElementById('chat-messages');
        
        // Load messages on page load
        loadMessages();
        
        // Auto-refresh messages every 3 seconds
        setInterval(loadMessages, 3000);
        
        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            const name = nameInput.value.trim();
            const message = messageInput.value.trim();
            if (!name || !message) return;
            
            try {
                const response = await fetch('/chat', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: `name=${encodeURIComponent(name)}&message=${encodeURIComponent(message)}`
                });
                
                if (response.ok) {
                    messageInput.value = '';
                    loadMessages();
                }
            } catch (error) {
                console.error('Error sending message:', error);
            }
        });
        
        async function loadMessages() {
            try {
                const response = await fetch('/chat/history');
                const messages = await response.json();
                renderMessages(messages);
            } catch (error) {
                console.error('Error loading messages:', error);
            }
        }
        
        function renderMessages(messages) {
            if (messages.length === 0) {
                messagesDiv.innerHTML = '<p style=""opacity: 0.6; text-align: center;"">No messages yet. Be the first to chat!</p>';
                return;
            }
            
            messagesDiv.innerHTML = messages.map(msg => `
                <div class=""message"">
                    <div class=""message-header"">
                        <span class=""message-name"">${escapeHtml(msg.name)}</span>
                        <span class=""message-time"">${formatTime(msg.timestamp)}</span>
                    </div>
                    <div class=""message-content"">${formatMessage(msg.content)}</div>
                </div>
            `).join('');
            
            messagesDiv.scrollTop = messagesDiv.scrollHeight;
        }
        
        function formatMessage(text) {
            text = escapeHtml(text);
            text = text.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
            text = text.replace(/\*(.+?)\*/g, '<em>$1</em>');
            text = text.replace(/\[(.+?)\]\((.+?)\)/g, '<a href=""$2"" target=""_blank"">$1</a>');
            return text;
        }
        
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        function formatTime(timestamp) {
            const date = new Date(timestamp);
            return date.toLocaleTimeString();
        }
    </script>
</body>
</html>"
        
        Dim buffer = Encoding.UTF8.GetBytes(html)
        response.ContentType = "text/html"
        response.ContentLength64 = buffer.Length
        response.StatusCode = 200
        response.OutputStream.Write(buffer, 0, buffer.Length)
        response.OutputStream.Close()
    End Sub
    
    Sub HandleChatPost(request As HttpListenerRequest, response As HttpListenerResponse)
        Try
            ' Read POST data
            Dim body As String
            Using reader As New StreamReader(request.InputStream, request.ContentEncoding)
                body = reader.ReadToEnd()
            End Using
            
            ' Parse form data
            Dim nameValue As String = ""
            Dim messageValue As String = ""
            
            Dim pairs = body.Split("&"c)
            For Each pair In pairs
                Dim keyValue = pair.Split("="c)
                If keyValue.Length = 2 Then
                    Dim key = HttpUtility.UrlDecode(keyValue(0))
                    Dim value = HttpUtility.UrlDecode(keyValue(1))
                    If key = "name" Then
                        nameValue = value
                    ElseIf key = "message" Then
                        messageValue = value
                    End If
                End If
            Next
            
            ' Add message to list
            If Not String.IsNullOrEmpty(nameValue) And Not String.IsNullOrEmpty(messageValue) Then
                Dim msg As New ChatMessage With {
                    .Name = nameValue,
                    .Content = messageValue,
                    .Timestamp = DateTime.Now
                }
                chatMessages.Add(msg)
                Console.WriteLine($"Chat: {nameValue} posted a message")
            End If
            
            SendResponse(response, "OK", 200)
        Catch ex As Exception
            Console.WriteLine($"Error handling chat post: {ex.Message}")
            SendResponse(response, "Error", 500)
        End Try
    End Sub
    
    Sub ServeChatHistory(response As HttpListenerResponse)
        Try
            Dim json As New StringBuilder()
            json.Append("[")
            
            For i As Integer = 0 To chatMessages.Count - 1
                Dim msg = chatMessages(i)
                If i > 0 Then json.Append(",")
                
                json.Append("{")
                json.Append($"""name"":""{JsonEscape(msg.Name)}"",")
                json.Append($"""content"":""{JsonEscape(msg.Content)}"",")
                json.Append($"""timestamp"":""{msg.Timestamp:o}""")
                json.Append("}")
            Next
            
            json.Append("]")
            
            Dim buffer = Encoding.UTF8.GetBytes(json.ToString())
            response.ContentType = "application/json"
            response.ContentLength64 = buffer.Length
            response.StatusCode = 200
            response.OutputStream.Write(buffer, 0, buffer.Length)
            response.OutputStream.Close()
        Catch ex As Exception
            Console.WriteLine($"Error serving chat history: {ex.Message}")
            SendResponse(response, "[]", 200)
        End Try
    End Sub
    
    Function JsonEscape(text As String) As String
        If String.IsNullOrEmpty(text) Then Return ""
        Return text.Replace("\", "\\").Replace("""", "\""").Replace(vbCr, "\r").Replace(vbLf, "\n").Replace(vbTab, "\t")
    End Function
    
    ' Authentication helpers
    Function GetCookieValue(request As HttpListenerRequest, cookieName As String) As String
        If request.Cookies(cookieName) IsNot Nothing Then
            Return request.Cookies(cookieName).Value
        End If
        Return Nothing
    End Function
    
    Sub SetAuthCookie(response As HttpListenerResponse, username As String, role As String)
        response.AppendHeader("Set-Cookie", $"username={username}; Path=/")
        response.AppendHeader("Set-Cookie", $"role={role}; Path=/")
    End Sub
    
    Sub ServeAuthPage(response As HttpListenerResponse)
        Dim html As String = "<!DOCTYPE html>
<html lang=""en"">
<head>
    <meta charset=""UTF-8"">
    <meta name=""viewport"" content=""width=device-width, initial-scale=1.0"">
    <title>Auth - Blackjack Table</title>
    <link rel=""stylesheet"" href=""/styles.css"">
    <style>
        .auth-container { max-width: 500px; margin: 0 auto; }
        .auth-board { background: rgba(255, 255, 255, 0.1); backdrop-filter: blur(10px); border-radius: 20px; padding: 2rem; box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2); border: 1px solid rgba(255, 255, 255, 0.18); margin-bottom: 2rem; }
        .auth-board h2 { color: #ffd700; margin-bottom: 1.5rem; font-size: 1.5rem; }
        .form-group { margin-bottom: 1rem; }
        .form-label { display: block; font-size: 0.9rem; font-weight: 600; margin-bottom: 0.5rem; color: #ffd700; }
        .form-input { width: 100%; padding: 0.8rem; font-size: 1rem; border: 2px solid rgba(255, 255, 255, 0.3); border-radius: 10px; background: rgba(255, 255, 255, 0.1); color: white; outline: none; transition: all 0.3s; }
        .form-input:focus { border-color: #ffd700; background: rgba(255, 255, 255, 0.15); }
        .auth-btn { width: 100%; padding: 1rem; font-size: 1rem; font-weight: 600; border: 2px solid #ffd700; border-radius: 10px; background: linear-gradient(135deg, #ffd700 0%, #ffed4e 100%); color: #1e3c72; cursor: pointer; transition: all 0.3s ease; margin-top: 1rem; }
        .auth-btn:hover { background: linear-gradient(135deg, #ffed4e 0%, #ffd700 100%); transform: translateY(-2px); box-shadow: 0 6px 20px rgba(255, 215, 0, 0.4); }
        .lobby-link { display: inline-block; margin-top: 1rem; color: #4fc3f7; text-decoration: none; }
        .lobby-link:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class=""container"">
        <header>
            <h1>🔐 Authentication</h1>
        </header>
        <main>
            <div class=""auth-container"">
                <div class=""auth-board"">
                    <h2>Sign Up</h2>
                    <form action=""/signup"" method=""POST"">
                        <div class=""form-group"">
                            <label class=""form-label"" for=""signup-username"">Username</label>
                            <input type=""text"" id=""signup-username"" name=""username"" class=""form-input"" required />
                        </div>
                        <div class=""form-group"">
                            <label class=""form-label"" for=""signup-password"">Password</label>
                            <input type=""password"" id=""signup-password"" name=""password"" class=""form-input"" required />
                        </div>
                        <button type=""submit"" class=""auth-btn"">Sign Up</button>
                    </form>
                </div>
                
                <div class=""auth-board"">
                    <h2>Login</h2>
                    <form action=""/login"" method=""POST"">
                        <div class=""form-group"">
                            <label class=""form-label"" for=""login-username"">Username</label>
                            <input type=""text"" id=""login-username"" name=""username"" class=""form-input"" required />
                        </div>
                        <div class=""form-group"">
                            <label class=""form-label"" for=""login-password"">Password</label>
                            <input type=""password"" id=""login-password"" name=""password"" class=""form-input"" required />
                        </div>
                        <button type=""submit"" class=""auth-btn"">Login</button>
                    </form>
                </div>
                
                <div style=""text-align: center;"">
                    <a href=""/"" class=""lobby-link"">← Back to Lobby</a>
                </div>
            </div>
        </main>
    </div>
</body>
</html>"
        
        Dim buffer = Encoding.UTF8.GetBytes(html)
        response.ContentType = "text/html"
        response.ContentLength64 = buffer.Length
        response.StatusCode = 200
        response.OutputStream.Write(buffer, 0, buffer.Length)
        response.OutputStream.Close()
    End Sub
    
    Sub HandleSignup(request As HttpListenerRequest, response As HttpListenerResponse)
        Try
            ' Read POST data
            Dim body As String
            Using reader As New StreamReader(request.InputStream, request.ContentEncoding)
                body = reader.ReadToEnd()
            End Using
            
            ' Parse form data
            Dim username As String = ""
            Dim password As String = ""
            
            Dim pairs = body.Split("&"c)
            For Each pair In pairs
                Dim keyValue = pair.Split("="c)
                If keyValue.Length = 2 Then
                    Dim key = HttpUtility.UrlDecode(keyValue(0))
                    Dim value = HttpUtility.UrlDecode(keyValue(1))
                    If key = "username" Then
                        username = value
                    ElseIf key = "password" Then
                        password = value
                    End If
                End If
            Next
            
            ' Check if user already exists
            Dim existingUser = users.Find(Function(u) u.Username = username)
            If existingUser IsNot Nothing Then
                SendResponse(response, "Username already exists", 400)
                Return
            End If
            
            ' Create new user
            Dim newUser As New User With {
                .Username = username,
                .Password = password,
                .Role = "player"
            }
            users.Add(newUser)
            Console.WriteLine($"New user signed up: {username}")
            
            ' Set auth cookie
            SetAuthCookie(response, username, "player")
            
            ' Redirect to lobby
            response.StatusCode = 302
            response.RedirectLocation = "/"
            response.Close()
        Catch ex As Exception
            Console.WriteLine($"Error handling signup: {ex.Message}")
            SendResponse(response, "Signup failed", 500)
        End Try
    End Sub
    
    Sub HandleLogin(request As HttpListenerRequest, response As HttpListenerResponse)
        Try
            ' Read POST data
            Dim body As String
            Using reader As New StreamReader(request.InputStream, request.ContentEncoding)
                body = reader.ReadToEnd()
            End Using
            
            ' Parse form data
            Dim username As String = ""
            Dim password As String = ""
            
            Dim pairs = body.Split("&"c)
            For Each pair In pairs
                Dim keyValue = pair.Split("="c)
                If keyValue.Length = 2 Then
                    Dim key = HttpUtility.UrlDecode(keyValue(0))
                    Dim value = HttpUtility.UrlDecode(keyValue(1))
                    If key = "username" Then
                        username = value
                    ElseIf key = "password" Then
                        password = value
                    End If
                End If
            Next
            
            ' Find user
            Dim user = users.Find(Function(u) u.Username = username And u.Password = password)
            If user Is Nothing Then
                SendResponse(response, "Invalid credentials", 401)
                Return
            End If
            
            Console.WriteLine($"User logged in: {username}")
            
            ' Set auth cookie
            SetAuthCookie(response, username, user.Role)
            
            ' Redirect to lobby
            response.StatusCode = 302
            response.RedirectLocation = "/"
            response.Close()
        Catch ex As Exception
            Console.WriteLine($"Error handling login: {ex.Message}")
            SendResponse(response, "Login failed", 500)
        End Try
    End Sub
    
    Sub ServeLobbyPage(request As HttpListenerRequest, response As HttpListenerResponse)
        ' Get logged-in user info from cookies
        Dim username = GetCookieValue(request, "username")
        Dim role = GetCookieValue(request, "role")
        
        Dim userInfo As String = ""
        If Not String.IsNullOrEmpty(username) Then
            userInfo = $"<div style=""text-align: center; margin-top: 1rem; opacity: 0.9;"">Logged in as <strong>{HttpUtility.HtmlEncode(username)}</strong> ({HttpUtility.HtmlEncode(role)})</div>"
        Else
            userInfo = "<div style=""text-align: center; margin-top: 1rem;""><a href=""/auth"" style=""color: #ffd700; text-decoration: none;"">Login / Sign Up →</a></div>"
        End If
        
        Dim html As String = $"<!DOCTYPE html>
<html lang=""en"">
<head>
    <meta charset=""UTF-8"">
    <meta name=""viewport"" content=""width=device-width, initial-scale=1.0"">
    <title>Blackjack Table Lobby</title>
    <link rel=""stylesheet"" href=""/styles.css"">
</head>
<body>
    <div class=""container"">
        <header>
            <h1>🎰 Blackjack Table Lobby</h1>
            <p class=""subtitle"">Choose Your Destination</p>
            {userInfo}
        </header>
        
        <main>
            <nav class=""lobby-nav"">
                <a href=""/navigate?url=/game"" class=""nav-button primary"">
                    🃏 Play Blackjack
                </a>
                <a href=""/navigate?url=/chat"" class=""nav-button"">
                    💬 Table Chat
                </a>
                <a href=""/navigate?url=/settings"" class=""nav-button"">
                    🎨 Card Themes
                </a>
                <a href=""/navigate?url=/background"" class=""nav-button"">
                    🖼️ Table Background
                </a>
                <a href=""/navigate?url=/dashboard"" class=""nav-button"">
                    📊 Dealer Dashboard
                </a>
                <a href=""/navigate?url=/logs"" class=""nav-button"">
                    📜 Game Logs
                </a>
            </nav>
        </main>
        
        <footer>
            <p>VB.NET + HttpListener | Port 3000</p>
        </footer>
    </div>
    
    <script src=""/app.js""></script>
</body>
</html>"
        
        Dim buffer = Encoding.UTF8.GetBytes(html)
        response.ContentType = "text/html"
        response.ContentLength64 = buffer.Length
        response.StatusCode = 200
        response.OutputStream.Write(buffer, 0, buffer.Length)
        response.OutputStream.Close()
    End Sub
    
    Sub ServeBackgroundPage(response As HttpListenerResponse)
        Dim html As String = "<!DOCTYPE html>
<html lang=""en"">
<head>
    <meta charset=""UTF-8"">
    <meta name=""viewport"" content=""width=device-width, initial-scale=1.0"">
    <title>Table Background</title>
    <link rel=""stylesheet"" href=""/styles.css"">
    <style>
        .back-link { display: inline-block; color: #ffd700; text-decoration: none; font-size: 1rem; margin-top: 0.5rem; transition: opacity 0.3s; }
        .back-link:hover { opacity: 0.8; }
        .background-board { background: rgba(255, 255, 255, 0.1); backdrop-filter: blur(10px); border-radius: 20px; padding: 2rem; box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2); border: 1px solid rgba(255, 255, 255, 0.18); max-width: 800px; margin: 0 auto; }
        .form-group { margin-bottom: 1.5rem; }
        .form-label { display: block; font-size: 1rem; font-weight: 600; margin-bottom: 0.5rem; color: #ffd700; }
        .form-input { width: 100%; padding: 0.8rem; font-size: 1rem; border: 2px solid rgba(255, 255, 255, 0.3); border-radius: 10px; background: rgba(255, 255, 255, 0.1); color: white; outline: none; transition: all 0.3s; }
        .form-input:focus { border-color: #ffd700; background: rgba(255, 255, 255, 0.15); }
        .preview-btn { padding: 1rem 2rem; font-size: 1rem; font-weight: 600; border: 2px solid #ffd700; border-radius: 10px; background: linear-gradient(135deg, #ffd700 0%, #ffed4e 100%); color: #1e3c72; cursor: pointer; transition: all 0.3s ease; }
        .preview-btn:hover { background: linear-gradient(135deg, #ffed4e 0%, #ffd700 100%); transform: translateY(-2px); box-shadow: 0 6px 20px rgba(255, 215, 0, 0.4); }
        .preview-area { margin-top: 2rem; padding: 2rem; background: rgba(0, 0, 0, 0.3); border-radius: 10px; text-align: center; min-height: 300px; display: flex; align-items: center; justify-content: center; }
        .preview-image { max-width: 100%; max-height: 400px; border-radius: 10px; display: none; }
        .preview-placeholder { opacity: 0.6; font-size: 1.1rem; }
        .hint { font-size: 0.85rem; opacity: 0.7; margin-top: 0.5rem; }
    </style>
</head>
<body>
    <div class=""container"">
        <header>
            <h1>🖼️ Table Background</h1>
            <a href=""/navigate?url=/"" class=""back-link"">← Back to Lobby</a>
        </header>
        <main>
            <div class=""background-board"">
                <div class=""form-group"">
                    <label class=""form-label"" for=""image-url"">Image URL</label>
                    <input type=""text"" id=""image-url"" class=""form-input"" placeholder=""https://example.com/table-felt.jpg"" />
                    <div class=""hint"">Enter a direct link to an image (jpg, png, gif, etc.)</div>
                </div>
                <button id=""preview-btn"" class=""preview-btn"">Preview Background</button>
                
                <div class=""preview-area"">
                    <div id=""placeholder"" class=""preview-placeholder"">Enter an image URL and click Preview</div>
                    <img id=""preview-image"" class=""preview-image"" />
                </div>
            </div>
        </main>
    </div>
    <script>
        const urlInput = document.getElementById('image-url');
        const previewBtn = document.getElementById('preview-btn');
        const previewImage = document.getElementById('preview-image');
        const placeholder = document.getElementById('placeholder');
        
        previewBtn.addEventListener('click', () => {
            const imageUrl = urlInput.value.trim();
            if (!imageUrl) {
                alert('Please enter an image URL');
                return;
            }
            
            // Use the proxy endpoint
            const proxyUrl = `/background/proxy?src=${encodeURIComponent(imageUrl)}`;
            
            // Show loading state
            placeholder.textContent = 'Loading...';
            previewImage.style.display = 'none';
            
            // Load the image
            const img = new Image();
            img.onload = () => {
                previewImage.src = proxyUrl;
                previewImage.style.display = 'block';
                placeholder.style.display = 'none';
            };
            img.onerror = () => {
                placeholder.textContent = 'Failed to load image. Please check the URL.';
                placeholder.style.display = 'block';
                previewImage.style.display = 'none';
            };
            img.src = proxyUrl;
        });
        
        // Allow Enter key to trigger preview
        urlInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                previewBtn.click();
            }
        });
    </script>
</body>
</html>"
        
        Dim buffer = Encoding.UTF8.GetBytes(html)
        response.ContentType = "text/html"
        response.ContentLength64 = buffer.Length
        response.StatusCode = 200
        response.OutputStream.Write(buffer, 0, buffer.Length)
        response.OutputStream.Close()
    End Sub
    
    Sub HandleBackgroundProxy(request As HttpListenerRequest, response As HttpListenerResponse)
        Try
            Dim srcUrl = request.QueryString("src")
            If String.IsNullOrEmpty(srcUrl) Then
                SendResponse(response, "Missing src parameter", 400)
                Return
            End If
            
            Console.WriteLine($"Proxying image: {srcUrl}")
            
            ' Fetch the image using HttpClient
            Dim task = httpClient.GetAsync(srcUrl)
            task.Wait()
            Dim httpResponse = task.Result
            
            If Not httpResponse.IsSuccessStatusCode Then
                SendResponse(response, "Failed to fetch image", 502)
                Return
            End If
            
            ' Get content type from the response
            Dim contentType = "image/jpeg"
            If httpResponse.Content.Headers.ContentType IsNot Nothing Then
                contentType = httpResponse.Content.Headers.ContentType.ToString()
            End If
            
            ' Read the image bytes
            Dim contentTask = httpResponse.Content.ReadAsByteArrayAsync()
            contentTask.Wait()
            Dim imageBytes = contentTask.Result
            
            ' Send the image to the client
            response.ContentType = contentType
            response.ContentLength64 = imageBytes.Length
            response.StatusCode = 200
            response.OutputStream.Write(imageBytes, 0, imageBytes.Length)
            response.OutputStream.Close()
        Catch ex As Exception
            Console.WriteLine($"Error proxying image: {ex.Message}")
            Try
                SendResponse(response, "Error fetching image", 500)
            Catch
                ' Response already closed
            End Try
        End Try
    End Sub
    
    Sub HandleGameRecord(request As HttpListenerRequest, response As HttpListenerResponse)
        Try
            Dim body As String
            Using reader As New StreamReader(request.InputStream, request.ContentEncoding)
                body = reader.ReadToEnd()
            End Using
            
            Dim result = HttpUtility.UrlDecode(body).Replace("result=", "")
            
            totalHandsDealt += 1
            
            If result = "player" Then
                playerWins += 1
            ElseIf result = "dealer" Then
                dealerWins += 1
            ElseIf result = "push" Then
                pushes += 1
            End If
            
            Console.WriteLine($"Game recorded: {result}. Total hands: {totalHandsDealt}, Player wins: {playerWins}, Dealer wins: {dealerWins}, Pushes: {pushes}")
            
            SendResponse(response, "OK", 200)
        Catch ex As Exception
            Console.WriteLine($"Error recording game: {ex.Message}")
            SendResponse(response, "Error recording game", 500)
        End Try
    End Sub
    
    Sub ServeDashboardPage(request As HttpListenerRequest, response As HttpListenerResponse)
        Dim role = GetCookieValue(request, "role")
        
        Dim html As String
        
        If role = "dealer" Then
            html = $"<!DOCTYPE html>
<html>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>Dealer Dashboard - Blackjack Table</title>
    <link rel='stylesheet' href='/styles.css'>
    <style>
        .dashboard-board {{
            background: rgba(0,0,0,0.8);
            border-radius: 15px;
            padding: 40px;
            max-width: 700px;
            margin: 40px auto;
            box-shadow: 0 10px 40px rgba(0,0,0,0.5);
        }}
        .dashboard-header {{
            text-align: center;
            margin-bottom: 30px;
        }}
        .dashboard-header h1 {{
            color: #ffd700;
            margin: 0 0 10px 0;
            font-size: 2.5em;
        }}
        .dashboard-header p {{
            color: #ccc;
            margin: 0;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 20px;
            margin: 30px 0;
        }}
        .stat-card {{
            background: rgba(255,255,255,0.05);
            border: 2px solid rgba(255,215,0,0.3);
            border-radius: 10px;
            padding: 25px;
            text-align: center;
        }}
        .stat-card.large {{
            grid-column: 1 / -1;
        }}
        .stat-label {{
            color: #999;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 10px;
        }}
        .stat-value {{
            color: #ffd700;
            font-size: 2.5em;
            font-weight: bold;
            margin: 0;
        }}
        .stat-subtext {{
            color: #bbb;
            font-size: 0.9em;
            margin-top: 5px;
        }}
        .win-rate {{
            display: flex;
            justify-content: space-around;
            margin-top: 15px;
        }}
        .win-rate-item {{
            text-align: center;
        }}
        .win-rate-item .label {{
            color: #999;
            font-size: 0.85em;
            margin-bottom: 5px;
        }}
        .win-rate-item .value {{
            color: #4CAF50;
            font-size: 1.3em;
            font-weight: bold;
        }}
        .win-rate-item.dealer .value {{
            color: #f44336;
        }}
        .win-rate-item.push .value {{
            color: #FF9800;
        }}
        .back-link {{
            display: inline-block;
            margin-top: 20px;
            color: #ffd700;
            text-decoration: none;
            padding: 10px 20px;
            border: 2px solid #ffd700;
            border-radius: 5px;
            transition: all 0.3s;
        }}
        .back-link:hover {{
            background: #ffd700;
            color: #000;
        }}
    </style>
</head>
<body>
    <div class='container'>
        <div class='dashboard-board'>
            <div class='dashboard-header'>
                <h1>🎰 Dealer Dashboard</h1>
                <p>Live game statistics and analytics</p>
            </div>
            
            <div class='stats-grid'>
                <div class='stat-card large'>
                    <div class='stat-label'>Total Hands Dealt</div>
                    <div class='stat-value'>{totalHandsDealt}</div>
                </div>
                
                <div class='stat-card'>
                    <div class='stat-label'>Player Wins</div>
                    <div class='stat-value'>{playerWins}</div>
                    <div class='stat-subtext'>{If(totalHandsDealt > 0, Math.Round(playerWins * 100.0 / totalHandsDealt, 1), 0)}%</div>
                </div>
                
                <div class='stat-card'>
                    <div class='stat-label'>Dealer Wins</div>
                    <div class='stat-value'>{dealerWins}</div>
                    <div class='stat-subtext'>{If(totalHandsDealt > 0, Math.Round(dealerWins * 100.0 / totalHandsDealt, 1), 0)}%</div>
                </div>
                
                <div class='stat-card large'>
                    <div class='stat-label'>Distribution</div>
                    <div class='win-rate'>
                        <div class='win-rate-item'>
                            <div class='label'>Player</div>
                            <div class='value'>{playerWins}</div>
                        </div>
                        <div class='win-rate-item dealer'>
                            <div class='label'>Dealer</div>
                            <div class='value'>{dealerWins}</div>
                        </div>
                        <div class='win-rate-item push'>
                            <div class='label'>Push</div>
                            <div class='value'>{pushes}</div>
                        </div>
                    </div>
                </div>
            </div>
            
            <div style='text-align: center;'>
                <a href='/navigate?url=/' class='back-link'>← Back to Lobby</a>
            </div>
        </div>
    </div>
</body>
</html>"
        Else
            html = $"<!DOCTYPE html>
<html>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>Access Denied - Blackjack Table</title>
    <link rel='stylesheet' href='/styles.css'>
    <style>
        .access-denied {{
            background: rgba(0,0,0,0.8);
            border-radius: 15px;
            padding: 60px 40px;
            max-width: 500px;
            margin: 100px auto;
            box-shadow: 0 10px 40px rgba(0,0,0,0.5);
            text-align: center;
        }}
        .access-denied h1 {{
            color: #f44336;
            font-size: 3em;
            margin: 0 0 20px 0;
        }}
        .access-denied p {{
            color: #ccc;
            font-size: 1.2em;
            margin: 0 0 30px 0;
        }}
        .back-link {{
            display: inline-block;
            margin-top: 20px;
            color: #ffd700;
            text-decoration: none;
            padding: 12px 30px;
            border: 2px solid #ffd700;
            border-radius: 5px;
            transition: all 0.3s;
            font-size: 1.1em;
        }}
        .back-link:hover {{
            background: #ffd700;
            color: #000;
        }}
    </style>
</head>
<body>
    <div class='container'>
        <div class='access-denied'>
            <h1>🚫</h1>
            <p>Access restricted to dealers only</p>
            <a href='/navigate?url=/' class='back-link'>← Back to Lobby</a>
        </div>
    </div>
</body>
</html>"
        End If
        
        Dim buffer = Encoding.UTF8.GetBytes(html)
        response.ContentType = "text/html"
        response.ContentLength64 = buffer.Length
        response.StatusCode = 200
        response.OutputStream.Write(buffer, 0, buffer.Length)
        response.OutputStream.Close()
    End Sub
End Module
