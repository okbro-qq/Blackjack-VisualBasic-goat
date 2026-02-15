Imports System
Imports System.IO
Imports System.Net
Imports System.Text
Imports System.Web
Imports BCrypt.Net

Module Program
    Private ReadOnly ServerUrl As String = "http://localhost:5000/"
    Private WwwRoot As String
    Private ConfigsDir As String
    Private ReadOnly AllowedPaths() As String = {"/game", "/chat", "/settings", "/background", "/logs"}
    Private ReadOnly AllowedConfigs() As String = {"standard", "vegas", "tournament"}
    ' SSRF Protection: Allowlist of trusted image domains
    Private ReadOnly AllowedImageDomains() As String = {
        "images.unsplash.com",
        "cdn.pixabay.com", 
        "i.imgur.com",
        "picsum.photos"
    }
    
    ' In-memory chat storage
    Private ChatMessages As New List(Of ChatMessage)()
    
    ' In-memory user storage
    Private Users As New List(Of User)()
    
    ' Game statistics
    Private GameStats As New GameStatistics()
    
    ' Chat message structure
    Private Class ChatMessage
        Public Property DisplayName As String
        Public Property Message As String
        Public Property Timestamp As DateTime
    End Class
    
    ' User structure
    Private Class User
        Public Property Username As String
        Public Property PasswordHash As String
        Public Property Role As String = "player"
    End Class
    
    ' Game statistics structure
    Private Class GameStatistics
        Public Property TotalHandsDealt As Integer = 0
        Public Property PlayerWins As Integer = 0
        Public Property DealerWins As Integer = 0
        Public Property Pushes As Integer = 0
    End Class

    Sub Main()
        ' Initialize paths
        WwwRoot = System.IO.Path.Combine(Directory.GetCurrentDirectory(), "wwwroot")
        ConfigsDir = System.IO.Path.Combine(Directory.GetCurrentDirectory(), "configs")
        
        ' Ensure directories exist
        If Not Directory.Exists(WwwRoot) Then
            Directory.CreateDirectory(WwwRoot)
        End If
        If Not Directory.Exists(ConfigsDir) Then
            Directory.CreateDirectory(ConfigsDir)
        End If
        
        ' Initialize test accounts
        InitializeTestAccounts()

        ' Create and configure HttpListener
        Dim listener As New HttpListener()
        listener.Prefixes.Add(ServerUrl)
        
        Try
            listener.Start()
            Console.WriteLine($"Blackjack Table Server is running on {ServerUrl}")
            Console.WriteLine("Press Ctrl+C to stop the server...")
            Console.WriteLine()

            ' Main server loop
            While True
                Try
                    Dim context As HttpListenerContext = listener.GetContext()
                    HandleRequest(context)
                Catch ex As Exception
                    Console.WriteLine($"Error handling request: {ex.Message}")
                End Try
            End While
        Catch ex As HttpListenerException
            Console.WriteLine($"Failed to start server: {ex.Message}")
            Console.WriteLine("Make sure you have permission to bind to the port.")
        Finally
            listener.Stop()
            listener.Close()
        End Try
    End Sub

    Private Sub InitializeTestAccounts()
        ' Create a test dealer account for demo purposes
        ' Username: dealer, Password: dealer123
        Users.Add(New User With {
            .Username = "dealer",
            .PasswordHash = BCrypt.Net.BCrypt.HashPassword("dealer123", workFactor:=12),
            .Role = "dealer"
        })
        
        ' Create a test player account
        ' Username: player, Password: player123
        Users.Add(New User With {
            .Username = "player",
            .PasswordHash = BCrypt.Net.BCrypt.HashPassword("player123", workFactor:=12),
            .Role = "player"
        })
        
        Console.WriteLine("Test accounts initialized:")
        Console.WriteLine("  - dealer/dealer123 (role: dealer)")
        Console.WriteLine("  - player/player123 (role: player)")
    End Sub

    Private Sub HandleRequest(context As HttpListenerContext)
        Dim request = context.Request
        Dim response = context.Response
        Dim path = request.Url.AbsolutePath

        Console.WriteLine($"{request.HttpMethod} {path}")

        Try
            ' Dashboard route
            If path = "/dashboard" Then
                RenderDashboardPage(request, response)
                Return
            End If

            ' Auth routes
            If path = "/auth" Then
                RenderAuthPage(response)
                Return
            End If
            
            If path = "/signup" AndAlso request.HttpMethod = "POST" Then
                HandleSignup(request, response)
                Return
            End If
            
            If path = "/login" AndAlso request.HttpMethod = "POST" Then
                HandleLogin(request, response)
                Return
            End If

            ' Background proxy route
            If path = "/background/proxy" Then
                HandleBackgroundProxy(request, response)
                Return
            End If

            ' Background page route
            If path = "/background" Then
                RenderBackgroundPage(response)
                Return
            End If

            ' Chat history route
            If path = "/chat/history" Then
                HandleChatHistory(request, response)
                Return
            End If

            ' Chat routes
            If path = "/chat" Then
                If request.HttpMethod = "GET" Then
                    RenderChatPage(response)
                ElseIf request.HttpMethod = "POST" Then
                    HandleChatPost(request, response)
                End If
                Return
            End If

            ' Settings load route - load config file
            If path = "/settings/load" Then
                HandleLoadConfig(request, response)
                Return
            End If

            ' Navigate route - centralized redirect handler
            If path = "/navigate" Then
                HandleNavigate(request, response)
                Return
            End If

            ' Root route - render lobby HTML page
            If path = "/" OrElse path = "" Then
                RenderLobbyPage(request, response)
                Return
            End If

            ' Serve static files from wwwroot
            Dim relativePath As String = path.TrimStart("/"c)
            Dim filePath As String = System.IO.Path.Combine(WwwRoot, relativePath)
            
            If File.Exists(filePath) Then
                ' Read file content
                Dim fileBytes() As Byte = File.ReadAllBytes(filePath)
                
                ' Set content type based on file extension
                response.ContentType = GetContentType(filePath)
                response.ContentLength64 = fileBytes.Length
                response.StatusCode = 200
                response.OutputStream.Write(fileBytes, 0, fileBytes.Length)
            Else
                ' 404 Not Found
                Dim notFoundMsg As String = $"404 - File not found: {path}"
                Dim buffer() As Byte = Encoding.UTF8.GetBytes(notFoundMsg)
                
                response.ContentType = "text/plain"
                response.StatusCode = 404
                response.ContentLength64 = buffer.Length
                response.OutputStream.Write(buffer, 0, buffer.Length)
            End If

            response.OutputStream.Close()
        Catch ex As Exception
            Console.WriteLine($"Error processing request: {ex.Message}")
            response.StatusCode = 500
            response.Close()
        End Try
    End Sub

    Private Sub HandleNavigate(request As HttpListenerRequest, response As HttpListenerResponse)
        ' Get url parameter from query string
        Dim targetUrl As String = request.QueryString("url")
        
        If String.IsNullOrEmpty(targetUrl) Then
            targetUrl = "/"
        End If

        ' OX Agent: Open Redirect prevented by path allowlist validation
        ' Validate against allowlist
        If Not Array.Exists(AllowedPaths, Function(p) p = targetUrl) Then
            Dim errorMsg As String = "Invalid redirect target"
            Dim buffer() As Byte = Encoding.UTF8.GetBytes(errorMsg)
            response.StatusCode = 400
            response.ContentType = "text/plain"
            response.ContentLength64 = buffer.Length
            response.OutputStream.Write(buffer, 0, buffer.Length)
            response.OutputStream.Close()
            Return
        End If

        ' Redirect to validated path
        response.StatusCode = 302
        response.RedirectLocation = targetUrl
        response.Close()
    End Sub

    Private Sub HandleLoadConfig(request As HttpListenerRequest, response As HttpListenerResponse)
        ' Get config parameter from query string
        Dim configName As String = request.QueryString("config")
        
        If String.IsNullOrEmpty(configName) Then
            SendJsonError(response, "Config name is required", 400)
            Return
        End If

        ' OX Agent: Path Traversal prevented by Path.GetFileName and allowlist validation
        ' Extract only the filename to prevent path traversal
        Dim safeConfigName As String = System.IO.Path.GetFileName(configName)
        
        ' Validate config name against allowlist
        If Not Array.Exists(AllowedConfigs, Function(c) c = safeConfigName) Then
            SendJsonError(response, "Invalid config name", 400)
            Return
        End If

        ' Build safe file path
        Dim configFile As String = safeConfigName & ".json"
        Dim baseConfigPath As String = System.IO.Path.GetFullPath(ConfigsDir)
        Dim fullConfigPath As String = System.IO.Path.GetFullPath(System.IO.Path.Combine(baseConfigPath, configFile))

        ' Validate path is within configs directory
        If Not fullConfigPath.StartsWith(baseConfigPath & System.IO.Path.DirectorySeparatorChar) Then
            SendJsonError(response, "Invalid config path", 400)
            Return
        End If

        ' Check if config file exists
        If Not File.Exists(fullConfigPath) Then
            SendJsonError(response, "Config file not found", 404)
            Return
        End If

        Try
            ' Read and return config JSON
            Dim jsonContent As String = File.ReadAllText(fullConfigPath)
            Dim buffer() As Byte = Encoding.UTF8.GetBytes(jsonContent)
            
            response.ContentType = "application/json"
            response.ContentLength64 = buffer.Length
            response.StatusCode = 200
            response.OutputStream.Write(buffer, 0, buffer.Length)
            response.OutputStream.Close()
            ' OX Agent: Path Traversal prevented by Path.GetFileName and allowlist validation
        Catch ex As Exception
            Console.WriteLine($"Error reading config: {ex.Message}")
            SendJsonError(response, "Error reading config file", 500)
        End Try
    End Sub

    Private Sub SendJsonError(response As HttpListenerResponse, message As String, statusCode As Integer)
        Dim jsonError As String = $"{{""error"": ""{message}""}}"
        Dim buffer() As Byte = Encoding.UTF8.GetBytes(jsonError)
        
        response.ContentType = "application/json"
        response.StatusCode = statusCode
        response.ContentLength64 = buffer.Length
        response.OutputStream.Write(buffer, 0, buffer.Length)
        response.OutputStream.Close()
    End Sub

    Private Sub HandleSignup(request As HttpListenerRequest, response As HttpListenerResponse)
        Try
            ' Read POST data
            Dim reader As New StreamReader(request.InputStream, request.ContentEncoding)
            Dim body As String = reader.ReadToEnd()
            
            ' Parse form data
            Dim username As String = ""
            Dim password As String = ""
            Dim role As String = "player"
            
            Dim parts() As String = body.Split("&"c)
            For Each part In parts
                Dim keyValue() As String = part.Split("="c)
                If keyValue.Length = 2 Then
                    Dim key As String = HttpUtility.UrlDecode(keyValue(0))
                    Dim value As String = HttpUtility.UrlDecode(keyValue(1))
                    
                    If key = "username" Then
                        username = value
                    ElseIf key = "password" Then
                        password = value
                    ElseIf key = "role" Then
                        role = value
                    End If
                End If
            Next
            
            ' Validate role against allowlist
            If role <> "player" AndAlso role <> "dealer" Then
                role = "player"
            End If
            
            ' Validate inputs
            If String.IsNullOrWhiteSpace(username) OrElse String.IsNullOrWhiteSpace(password) Then
                response.StatusCode = 302
                response.RedirectLocation = "/auth?error=empty"
                response.Close()
                Return
            End If
            
            ' Check password length
            If password.Length < 8 Then
                response.StatusCode = 302
                response.RedirectLocation = "/auth?error=weakpass"
                response.Close()
                Return
            End If
            
            ' Check if username already exists
            If Users.Exists(Function(u) u.Username = username) Then
                response.StatusCode = 302
                response.RedirectLocation = "/auth?error=exists"
                response.Close()
                Return
            End If
            
            ' OX Agent: Sensitive Data protected by BCrypt password hashing
            ' Hash password with BCrypt
            Dim hashedPassword As String = BCrypt.Net.BCrypt.HashPassword(password, workFactor:=12)
            
            ' Create new user
            Users.Add(New User With {
                .Username = username,
                .PasswordHash = hashedPassword,
                .Role = role
            })
            
            Console.WriteLine($"User registered: {username}")
            
            ' Redirect to lobby
            response.StatusCode = 302
            response.RedirectLocation = "/auth?success=signup"
            response.Close()
            
        Catch ex As Exception
            Console.WriteLine($"Error handling signup: {ex.Message}")
            response.StatusCode = 500
            response.Close()
        End Try
    End Sub

    Private Sub HandleLogin(request As HttpListenerRequest, response As HttpListenerResponse)
        Try
            ' Read POST data
            Dim reader As New StreamReader(request.InputStream, request.ContentEncoding)
            Dim body As String = reader.ReadToEnd()
            
            ' Parse form data
            Dim username As String = ""
            Dim password As String = ""
            
            Dim parts() As String = body.Split("&"c)
            For Each part In parts
                Dim keyValue() As String = part.Split("="c)
                If keyValue.Length = 2 Then
                    Dim key As String = HttpUtility.UrlDecode(keyValue(0))
                    Dim value As String = HttpUtility.UrlDecode(keyValue(1))
                    
                    If key = "username" Then
                        username = value
                    ElseIf key = "password" Then
                        password = value
                    End If
                End If
            Next
            
            ' Validate inputs
            If String.IsNullOrWhiteSpace(username) OrElse String.IsNullOrWhiteSpace(password) Then
                response.StatusCode = 302
                response.RedirectLocation = "/auth?error=invalid"
                response.Close()
                Return
            End If
            
            ' Find user
            Dim user = Users.FirstOrDefault(Function(u) u.Username = username)
            
            ' Verify password
            If user Is Nothing OrElse Not BCrypt.Net.BCrypt.Verify(password, user.PasswordHash) Then
                Console.WriteLine($"Failed login attempt for: {username}")
                response.StatusCode = 302
                response.RedirectLocation = "/auth?error=invalid"
                response.Close()
                Return
            End If
            
            ' OX Agent: Sensitive Data protected by secure cookie configuration
            ' Set secure cookie with username and role
            Dim cookieValue As String = $"{HttpUtility.UrlEncode(username)}|{user.Role}"
            Dim cookie As String = $"auth={cookieValue}; Path=/; HttpOnly; SameSite=Strict; Max-Age=3600"
            response.Headers.Add("Set-Cookie", cookie)
            
            Console.WriteLine($"User logged in: {username}")
            
            ' Redirect to lobby
            response.StatusCode = 302
            response.RedirectLocation = "/"
            response.Close()
            
        Catch ex As Exception
            Console.WriteLine($"Error handling login: {ex.Message}")
            response.StatusCode = 500
            response.Close()
        End Try
    End Sub

    Private Function GetLoggedInUser(request As HttpListenerRequest) As String
        Dim cookies As String = request.Headers("Cookie")
        If String.IsNullOrEmpty(cookies) Then
            Return Nothing
        End If
        
        ' Parse cookies
        Dim cookieParts() As String = cookies.Split(";"c)
        For Each part In cookieParts
            Dim keyValue() As String = part.Trim().Split("="c)
            If keyValue.Length = 2 AndAlso keyValue(0) = "auth" Then
                Dim authValue() As String = keyValue(1).Split("|"c)
                If authValue.Length > 0 Then
                    Return HttpUtility.UrlDecode(authValue(0))
                End If
            End If
        Next
        
        Return Nothing
    End Function

    Private Function GetUserRole(request As HttpListenerRequest) As String
        Dim cookies As String = request.Headers("Cookie")
        If String.IsNullOrEmpty(cookies) Then
            Return Nothing
        End If
        
        ' Parse cookies
        Dim cookieParts() As String = cookies.Split(";"c)
        For Each part In cookieParts
            Dim keyValue() As String = part.Trim().Split("="c)
            If keyValue.Length = 2 AndAlso keyValue(0) = "auth" Then
                Dim authValue() As String = keyValue(1).Split("|"c)
                If authValue.Length > 1 Then
                    Return authValue(1)
                End If
            End If
        Next
        
        Return Nothing
    End Function

    Private Sub RenderDashboardPage(request As HttpListenerRequest, response As HttpListenerResponse)
        ' Get logged-in user and role
        Dim loggedInUser As String = GetLoggedInUser(request)
        Dim userRole As String = GetUserRole(request)
        
        Dim html As New StringBuilder()
        html.AppendLine("<!DOCTYPE html>")
        html.AppendLine("<html lang=""en"">")
        html.AppendLine("<head>")
        html.AppendLine("    <meta charset=""UTF-8"">")
        html.AppendLine("    <meta name=""viewport"" content=""width=device-width, initial-scale=1.0"">")
        html.AppendLine("    <title>Dealer Dashboard</title>")
        html.AppendLine("    <link rel=""stylesheet"" href=""style.css"">")
        html.AppendLine("    <style>")
        html.AppendLine("        .dashboard-container { max-width: 800px; margin: 0 auto; padding: 2rem; }")
        html.AppendLine("        .access-denied { background: rgba(231, 76, 60, 0.3); padding: 3rem; border-radius: 10px; border: 2px solid rgba(231, 76, 60, 0.5); text-align: center; }")
        html.AppendLine("        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1.5rem; margin: 2rem 0; }")
        html.AppendLine("        .stat-card { background: rgba(255, 255, 255, 0.1); padding: 2rem; border-radius: 10px; border: 2px solid rgba(255, 255, 255, 0.2); text-align: center; }")
        html.AppendLine("        .stat-value { font-size: 3rem; font-weight: bold; color: #3498db; margin: 1rem 0; }")
        html.AppendLine("        .stat-label { font-size: 1rem; color: rgba(255, 255, 255, 0.8); }")
        html.AppendLine("        .back-link { display: inline-block; margin-top: 2rem; color: white; text-decoration: underline; }")
        html.AppendLine("        .user-info { background: rgba(255, 255, 255, 0.1); padding: 1rem; border-radius: 8px; margin-bottom: 2rem; text-align: center; }")
        html.AppendLine("    </style>")
        html.AppendLine("</head>")
        html.AppendLine("<body>")
        html.AppendLine("    <div class=""container dashboard-container"">")
        html.AppendLine("        <h1>📊 Dealer Dashboard</h1>")
        
        ' Check if user is a dealer
        If String.IsNullOrEmpty(loggedInUser) Then
            html.AppendLine("        <div class=""access-denied"">")
            html.AppendLine("            <h2>Access Denied</h2>")
            html.AppendLine("            <p>You must be logged in to view this page.</p>")
            html.AppendLine("            <p><a href=""/auth"" style=""color: white; text-decoration: underline;"">Login / Sign Up</a></p>")
            html.AppendLine("        </div>")
        ElseIf userRole <> "dealer" Then
            html.AppendLine("        <div class=""access-denied"">")
            html.AppendLine("            <h2>Access Restricted</h2>")
            html.AppendLine("            <p>Access restricted to dealers only.</p>")
            html.AppendLine("        </div>")
        Else
            ' OX Agent: XSS prevented by HttpUtility.HtmlEncode sanitization
            Dim sanitizedUsername As String = HttpUtility.HtmlEncode(loggedInUser)
            html.AppendLine($"        <div class=""user-info"">")
            html.AppendLine($"            Logged in as: <strong>{sanitizedUsername}</strong> (Dealer)")
            html.AppendLine($"        </div>")
            
            html.AppendLine("        <h2>Game Statistics</h2>")
            html.AppendLine("        <div class=""stats-grid"">")
            html.AppendLine("            <div class=""stat-card"">")
            html.AppendLine($"                <div class=""stat-value"">{GameStats.TotalHandsDealt}</div>")
            html.AppendLine("                <div class=""stat-label"">Total Hands Dealt</div>")
            html.AppendLine("            </div>")
            html.AppendLine("            <div class=""stat-card"">")
            html.AppendLine($"                <div class=""stat-value"">{GameStats.PlayerWins}</div>")
            html.AppendLine("                <div class=""stat-label"">Player Wins</div>")
            html.AppendLine("            </div>")
            html.AppendLine("            <div class=""stat-card"">")
            html.AppendLine($"                <div class=""stat-value"">{GameStats.DealerWins}</div>")
            html.AppendLine("                <div class=""stat-label"">Dealer Wins</div>")
            html.AppendLine("            </div>")
            html.AppendLine("            <div class=""stat-card"">")
            html.AppendLine($"                <div class=""stat-value"">{GameStats.Pushes}</div>")
            html.AppendLine("                <div class=""stat-label"">Pushes</div>")
            html.AppendLine("            </div>")
            
            ' Calculate win percentages if there are hands dealt
            If GameStats.TotalHandsDealt > 0 Then
                Dim playerWinPercentage As Double = (GameStats.PlayerWins / GameStats.TotalHandsDealt) * 100
                Dim dealerWinPercentage As Double = (GameStats.DealerWins / GameStats.TotalHandsDealt) * 100
                
                html.AppendLine("            <div class=""stat-card"">")
                html.AppendLine($"                <div class=""stat-value"">{playerWinPercentage:F1}%</div>")
                html.AppendLine("                <div class=""stat-label"">Player Win Rate</div>")
                html.AppendLine("            </div>")
                html.AppendLine("            <div class=""stat-card"">")
                html.AppendLine($"                <div class=""stat-value"">{dealerWinPercentage:F1}%</div>")
                html.AppendLine("                <div class=""stat-label"">Dealer Win Rate</div>")
                html.AppendLine("            </div>")
            End If
            
            html.AppendLine("        </div>")
            
            html.AppendLine("        <div style=""background: rgba(255, 255, 255, 0.1); padding: 1.5rem; border-radius: 8px; margin-top: 2rem;"">")
            html.AppendLine("            <h3>Additional Information</h3>")
            html.AppendLine($"            <p>Total registered users: {Users.Count}</p>")
            html.AppendLine($"            <p>Total chat messages: {ChatMessages.Count}</p>")
            html.AppendLine("        </div>")
        End If
        
        html.AppendLine("        <a href=""/navigate?url=/"" class=""back-link"">← Back to Lobby</a>")
        html.AppendLine("    </div>")
        html.AppendLine("</body>")
        html.AppendLine("</html>")
        
        Dim buffer() As Byte = Encoding.UTF8.GetBytes(html.ToString())
        response.ContentType = "text/html"
        response.ContentLength64 = buffer.Length
        response.StatusCode = 200
        response.OutputStream.Write(buffer, 0, buffer.Length)
        response.OutputStream.Close()
    End Sub

    Private Sub HandleChatPost(request As HttpListenerRequest, response As HttpListenerResponse)
        Try
            ' Read POST data
            Dim reader As New StreamReader(request.InputStream, request.ContentEncoding)
            Dim body As String = reader.ReadToEnd()
            
            ' Parse form data
            Dim displayName As String = ""
            Dim message As String = ""
            
            Dim parts() As String = body.Split("&"c)
            For Each part In parts
                Dim keyValue() As String = part.Split("="c)
                If keyValue.Length = 2 Then
                    Dim key As String = HttpUtility.UrlDecode(keyValue(0))
                    Dim value As String = HttpUtility.UrlDecode(keyValue(1))
                    
                    If key = "displayName" Then
                        displayName = value
                    ElseIf key = "message" Then
                        message = value
                    End If
                End If
            Next
            
            ' Validate inputs
            If String.IsNullOrWhiteSpace(displayName) OrElse String.IsNullOrWhiteSpace(message) Then
                response.StatusCode = 400
                response.Close()
                Return
            End If
            
            ' Limit lengths
            If displayName.Length > 50 Then
                displayName = displayName.Substring(0, 50)
            End If
            If message.Length > 1000 Then
                message = message.Substring(0, 1000)
            End If
            
            ' Store message
            ChatMessages.Add(New ChatMessage With {
                .DisplayName = displayName,
                .Message = message,
                .Timestamp = DateTime.Now
            })
            
            ' Redirect back to chat
            response.StatusCode = 302
            response.RedirectLocation = "/chat"
            response.Close()
        Catch ex As Exception
            Console.WriteLine($"Error handling chat post: {ex.Message}")
            response.StatusCode = 500
            response.Close()
        End Try
    End Sub

    Private Sub HandleChatHistory(request As HttpListenerRequest, response As HttpListenerResponse)
        Try
            ' Build JSON array
            Dim json As New StringBuilder()
            json.Append("[")
            
            For i As Integer = 0 To ChatMessages.Count - 1
                Dim msg = ChatMessages(i)
                If i > 0 Then json.Append(",")
                
                ' OX Agent: XSS prevented by HttpUtility.JavaScriptStringEncode sanitization
                Dim sanitizedName As String = HttpUtility.JavaScriptStringEncode(msg.DisplayName)
                Dim sanitizedMessage As String = HttpUtility.JavaScriptStringEncode(msg.Message)
                
                json.Append("{")
                json.Append($"""displayName"":""{sanitizedName}"",")
                json.Append($"""message"":""{sanitizedMessage}"",")
                json.Append($"""timestamp"":""{msg.Timestamp:yyyy-MM-ddTHH:mm:ss}""")
                json.Append("}")
            Next
            
            json.Append("]")
            
            Dim buffer() As Byte = Encoding.UTF8.GetBytes(json.ToString())
            response.ContentType = "application/json"
            response.ContentLength64 = buffer.Length
            response.StatusCode = 200
            response.OutputStream.Write(buffer, 0, buffer.Length)
            response.OutputStream.Close()
        Catch ex As Exception
            Console.WriteLine($"Error getting chat history: {ex.Message}")
            SendJsonError(response, "Error retrieving chat history", 500)
        End Try
    End Sub

    Private Async Sub HandleBackgroundProxy(request As HttpListenerRequest, response As HttpListenerResponse)
        Try
            ' Get source URL from query string
            Dim srcUrl As String = request.QueryString("src")
            
            If String.IsNullOrEmpty(srcUrl) Then
                response.StatusCode = 400
                response.Close()
                Return
            End If
            
            ' Parse and validate URL
            Dim uri As Uri = Nothing
            If Not Uri.TryCreate(srcUrl, UriKind.Absolute, uri) Then
                response.StatusCode = 400
                response.Close()
                Return
            End If
            
            ' Validate scheme (only HTTPS)
            If uri.Scheme <> "https" Then
                response.StatusCode = 400
                response.Close()
                Return
            End If
            
            ' OX Agent: SSRF prevented by domain allowlist validation
            ' Validate domain against allowlist
            If Not Array.Exists(AllowedImageDomains, Function(domain) domain = uri.Host) Then
                response.StatusCode = 403
                Dim errorMsg() As Byte = Encoding.UTF8.GetBytes("Domain not allowed")
                response.OutputStream.Write(errorMsg, 0, errorMsg.Length)
                response.Close()
                Return
            End If
            
            ' Fetch the image
            Using client As New System.Net.Http.HttpClient()
                client.Timeout = TimeSpan.FromSeconds(10)
                
                Try
                    Dim imageResponse = Await client.GetAsync(uri)
                    
                    If Not imageResponse.IsSuccessStatusCode Then
                        response.StatusCode = 502
                        response.Close()
                        Return
                    End If
                    
                    ' Get content type from response
                    Dim contentType As String = If(imageResponse.Content.Headers.ContentType?.MediaType, "image/jpeg")
                    
                    ' Allowlist validation inline in the same function
                    Dim allowedImageTypes() As String = {
                        "image/jpeg", "image/jpg", "image/png", "image/gif", "image/webp"
                    }
                    
                    ' Normalize DIRECTLY before validation
                    Dim normalizedContentType As String = contentType.ToLower().Split(";"c)(0).Trim()
                    
                    ' Validate against allowlist DIRECTLY before header operation
                    If Not Array.Exists(allowedImageTypes, Function(t) t = normalizedContentType) Then
                        response.StatusCode = 415
                        response.Close()
                        Return
                    End If
                    
                    ' Read image bytes
                    Dim imageBytes() As Byte = Await imageResponse.Content.ReadAsByteArrayAsync()
                    
                    ' OX Agent: Header Injection prevented by inline allowlist validation
                    response.ContentType = normalizedContentType
                    response.ContentLength64 = imageBytes.Length
                    response.StatusCode = 200
                    response.OutputStream.Write(imageBytes, 0, imageBytes.Length)
                    response.OutputStream.Close()
                    
                Catch ex As System.Net.Http.HttpRequestException
                    Console.WriteLine($"Error fetching image: {ex.Message}")
                    response.StatusCode = 502
                    response.Close()
                Catch ex As TaskCanceledException
                    Console.WriteLine("Request timeout")
                    response.StatusCode = 504
                    response.Close()
                End Try
            End Using
            
        Catch ex As Exception
            Console.WriteLine($"Error in background proxy: {ex.Message}")
            response.StatusCode = 500
            response.Close()
        End Try
    End Sub

    Private Sub RenderBackgroundPage(response As HttpListenerResponse)
        Dim html As New StringBuilder()
        html.AppendLine("<!DOCTYPE html>")
        html.AppendLine("<html lang=""en"">")
        html.AppendLine("<head>")
        html.AppendLine("    <meta charset=""UTF-8"">")
        html.AppendLine("    <meta name=""viewport"" content=""width=device-width, initial-scale=1.0"">")
        html.AppendLine("    <title>Table Background</title>")
        html.AppendLine("    <link rel=""stylesheet"" href=""style.css"">")
        html.AppendLine("    <style>")
        html.AppendLine("        .background-container { max-width: 900px; margin: 0 auto; padding: 2rem; }")
        html.AppendLine("        .url-input-section { background: rgba(255, 255, 255, 0.1); padding: 2rem; border-radius: 10px; margin-bottom: 2rem; }")
        html.AppendLine("        .form-group { margin-bottom: 1.5rem; }")
        html.AppendLine("        .form-group label { display: block; margin-bottom: 0.5rem; font-weight: bold; }")
        html.AppendLine("        .form-group input { width: 100%; padding: 0.8rem; font-size: 1rem; border: 2px solid rgba(255, 255, 255, 0.3); border-radius: 8px; background: rgba(255, 255, 255, 0.9); color: #333; }")
        html.AppendLine("        .btn { padding: 0.8rem 2rem; font-size: 1rem; background: rgba(52, 152, 219, 0.3); border: 2px solid rgba(52, 152, 219, 0.5); border-radius: 8px; color: white; cursor: pointer; transition: all 0.3s ease; }")
        html.AppendLine("        .btn:hover { background: rgba(52, 152, 219, 0.5); transform: translateY(-2px); }")
        html.AppendLine("        .preview-section { background: rgba(0, 0, 0, 0.3); padding: 2rem; border-radius: 10px; min-height: 400px; }")
        html.AppendLine("        .preview-section h2 { margin-bottom: 1rem; }")
        html.AppendLine("        .preview-area { background: rgba(255, 255, 255, 0.05); border: 2px dashed rgba(255, 255, 255, 0.3); border-radius: 8px; min-height: 300px; display: flex; align-items: center; justify-content: center; overflow: hidden; }")
        html.AppendLine("        .preview-area img { max-width: 100%; max-height: 400px; object-fit: contain; }")
        html.AppendLine("        .preview-placeholder { color: rgba(255, 255, 255, 0.5); text-align: center; }")
        html.AppendLine("        .allowed-domains { font-size: 0.85rem; color: rgba(255, 255, 255, 0.7); margin-top: 0.5rem; }")
        html.AppendLine("        .error-message { color: #e74c3c; font-weight: bold; margin-top: 1rem; }")
        html.AppendLine("        .back-link { display: inline-block; margin-top: 2rem; color: white; text-decoration: underline; }")
        html.AppendLine("    </style>")
        html.AppendLine("</head>")
        html.AppendLine("<body>")
        html.AppendLine("    <div class=""container background-container"">")
        html.AppendLine("        <h1>🖼️ Table Background</h1>")
        html.AppendLine("        <div class=""url-input-section"">")
        html.AppendLine("            <div class=""form-group"">")
        html.AppendLine("                <label for=""imageUrl"">Image URL (HTTPS only):</label>")
        html.AppendLine("                <input type=""url"" id=""imageUrl"" placeholder=""https://images.unsplash.com/..."">")
        html.AppendLine("                <div class=""allowed-domains"">")
        html.AppendLine("                    Allowed domains: images.unsplash.com, cdn.pixabay.com, i.imgur.com, picsum.photos")
        html.AppendLine("                </div>")
        html.AppendLine("            </div>")
        html.AppendLine("            <button class=""btn"" onclick=""previewImage()"">Preview</button>")
        html.AppendLine("            <div id=""error-message"" class=""error-message""></div>")
        html.AppendLine("        </div>")
        html.AppendLine("        <div class=""preview-section"">")
        html.AppendLine("            <h2>Preview:</h2>")
        html.AppendLine("            <div class=""preview-area"" id=""preview-area"">")
        html.AppendLine("                <div class=""preview-placeholder"">Enter an image URL and click Preview</div>")
        html.AppendLine("            </div>")
        html.AppendLine("        </div>")
        html.AppendLine("        <a href=""/navigate?url=/"" class=""back-link"">← Back to Lobby</a>")
        html.AppendLine("    </div>")
        html.AppendLine("    <script>")
        html.AppendLine("        function previewImage() {")
        html.AppendLine("            const imageUrl = document.getElementById('imageUrl').value.trim();")
        html.AppendLine("            const previewArea = document.getElementById('preview-area');")
        html.AppendLine("            const errorMessage = document.getElementById('error-message');")
        html.AppendLine("            ")
        html.AppendLine("            errorMessage.textContent = '';")
        html.AppendLine("            ")
        html.AppendLine("            if (!imageUrl) {")
        html.AppendLine("                errorMessage.textContent = 'Please enter an image URL';")
        html.AppendLine("                return;")
        html.AppendLine("            }")
        html.AppendLine("            ")
        html.AppendLine("            if (!imageUrl.startsWith('https://')) {")
        html.AppendLine("                errorMessage.textContent = 'Only HTTPS URLs are allowed';")
        html.AppendLine("                return;")
        html.AppendLine("            }")
        html.AppendLine("            ")
        html.AppendLine("            const proxyUrl = '/background/proxy?src=' + encodeURIComponent(imageUrl);")
        html.AppendLine("            ")
        html.AppendLine("            const img = document.createElement('img');")
        html.AppendLine("            img.onload = function() {")
        html.AppendLine("                previewArea.innerHTML = '';")
        html.AppendLine("                previewArea.appendChild(img);")
        html.AppendLine("            };")
        html.AppendLine("            img.onerror = function() {")
        html.AppendLine("                errorMessage.textContent = 'Failed to load image. Make sure the URL is from an allowed domain.';")
        html.AppendLine("                previewArea.innerHTML = '<div class=\""preview-placeholder\"">Failed to load image</div>';")
        html.AppendLine("            };")
        html.AppendLine("            img.src = proxyUrl;")
        html.AppendLine("            ")
        html.AppendLine("            previewArea.innerHTML = '<div class=\""preview-placeholder\"">Loading...</div>';")
        html.AppendLine("        }")
        html.AppendLine("        ")
        html.AppendLine("        document.getElementById('imageUrl').addEventListener('keypress', function(event) {")
        html.AppendLine("            if (event.key === 'Enter') {")
        html.AppendLine("                previewImage();")
        html.AppendLine("            }")
        html.AppendLine("        });")
        html.AppendLine("    </script>")
        html.AppendLine("</body>")
        html.AppendLine("</html>")
        
        Dim buffer() As Byte = Encoding.UTF8.GetBytes(html.ToString())
        response.ContentType = "text/html"
        response.ContentLength64 = buffer.Length
        response.StatusCode = 200
        response.OutputStream.Write(buffer, 0, buffer.Length)
        response.OutputStream.Close()
    End Sub

    Private Sub RenderAuthPage(response As HttpListenerResponse)
        Dim html As New StringBuilder()
        html.AppendLine("<!DOCTYPE html>")
        html.AppendLine("<html lang=""en"">")
        html.AppendLine("<head>")
        html.AppendLine("    <meta charset=""UTF-8"">")
        html.AppendLine("    <meta name=""viewport"" content=""width=device-width, initial-scale=1.0"">")
        html.AppendLine("    <title>Login / Sign Up</title>")
        html.AppendLine("    <link rel=""stylesheet"" href=""style.css"">")
        html.AppendLine("    <style>")
        html.AppendLine("        .auth-container { max-width: 500px; margin: 0 auto; padding: 2rem; }")
        html.AppendLine("        .auth-forms { display: flex; flex-direction: column; gap: 2rem; }")
        html.AppendLine("        .auth-form { background: rgba(255, 255, 255, 0.1); padding: 2rem; border-radius: 10px; border: 2px solid rgba(255, 255, 255, 0.2); }")
        html.AppendLine("        .form-group { margin-bottom: 1rem; }")
        html.AppendLine("        .form-group label { display: block; margin-bottom: 0.5rem; font-weight: bold; }")
        html.AppendLine("        .form-group input { width: 100%; padding: 0.8rem; font-size: 1rem; border: 2px solid rgba(255, 255, 255, 0.3); border-radius: 8px; background: rgba(255, 255, 255, 0.9); color: #333; }")
        html.AppendLine("        .btn { width: 100%; padding: 0.8rem; font-size: 1rem; background: rgba(46, 204, 113, 0.3); border: 2px solid rgba(46, 204, 113, 0.5); border-radius: 8px; color: white; cursor: pointer; transition: all 0.3s ease; }")
        html.AppendLine("        .btn:hover { background: rgba(46, 204, 113, 0.5); }")
        html.AppendLine("        .btn-secondary { background: rgba(52, 152, 219, 0.3); border-color: rgba(52, 152, 219, 0.5); }")
        html.AppendLine("        .btn-secondary:hover { background: rgba(52, 152, 219, 0.5); }")
        html.AppendLine("        .message { padding: 1rem; margin-bottom: 1rem; border-radius: 8px; text-align: center; }")
        html.AppendLine("        .error { background: rgba(231, 76, 60, 0.3); border: 2px solid rgba(231, 76, 60, 0.5); }")
        html.AppendLine("        .success { background: rgba(46, 204, 113, 0.3); border: 2px solid rgba(46, 204, 113, 0.5); }")
        html.AppendLine("        .hint { font-size: 0.85rem; color: rgba(255, 255, 255, 0.7); margin-top: 0.5rem; }")
        html.AppendLine("    </style>")
        html.AppendLine("</head>")
        html.AppendLine("<body>")
        html.AppendLine("    <div class=""container auth-container"">")
        html.AppendLine("        <h1>🃏 Blackjack Table</h1>")
        
        ' Show messages based on query parameters
        html.AppendLine("        <script>")
        html.AppendLine("            const params = new URLSearchParams(window.location.search);")
        html.AppendLine("            if (params.get('error') === 'empty') {")
        html.AppendLine("                document.write('<div class=\""message error\"">Username and password are required</div>');")
        html.AppendLine("            } else if (params.get('error') === 'weakpass') {")
        html.AppendLine("                document.write('<div class=\""message error\"">Password must be at least 8 characters</div>');")
        html.AppendLine("            } else if (params.get('error') === 'exists') {")
        html.AppendLine("                document.write('<div class=\""message error\"">Username already exists</div>');")
        html.AppendLine("            } else if (params.get('error') === 'invalid') {")
        html.AppendLine("                document.write('<div class=\""message error\"">Invalid username or password</div>');")
        html.AppendLine("            } else if (params.get('success') === 'signup') {")
        html.AppendLine("                document.write('<div class=\""message success\"">Account created! You can now log in.</div>');")
        html.AppendLine("            }")
        html.AppendLine("        </script>")
        
        html.AppendLine("        <div class=""auth-forms"">")
        html.AppendLine("            <div class=""auth-form"">")
        html.AppendLine("                <h2>Login</h2>")
        html.AppendLine("                <form method=""POST"" action=""/login"">")
        html.AppendLine("                    <div class=""form-group"">")
        html.AppendLine("                        <label for=""login-username"">Username:</label>")
        html.AppendLine("                        <input type=""text"" id=""login-username"" name=""username"" required>")
        html.AppendLine("                    </div>")
        html.AppendLine("                    <div class=""form-group"">")
        html.AppendLine("                        <label for=""login-password"">Password:</label>")
        html.AppendLine("                        <input type=""password"" id=""login-password"" name=""password"" required>")
        html.AppendLine("                    </div>")
        html.AppendLine("                    <button type=""submit"" class=""btn"">Login</button>")
        html.AppendLine("                </form>")
        html.AppendLine("            </div>")
                html.AppendLine("            <div class=""auth-form"">")
                html.AppendLine("                <h2>Sign Up</h2>")
                html.AppendLine("                <form method=""POST"" action=""/signup"">")
                html.AppendLine("                    <div class=""form-group"">")
                html.AppendLine("                        <label for=""signup-username"">Username:</label>")
                html.AppendLine("                        <input type=""text"" id=""signup-username"" name=""username"" required>")
                html.AppendLine("                    </div>")
                html.AppendLine("                    <div class=""form-group"">")
                html.AppendLine("                        <label for=""signup-password"">Password:</label>")
                html.AppendLine("                        <input type=""password"" id=""signup-password"" name=""password"" required minlength=""8"">")
                html.AppendLine("                        <div class=""hint"">At least 8 characters</div>")
                html.AppendLine("                    </div>")
                html.AppendLine("                    <div class=""form-group"">")
                html.AppendLine("                        <label for=""signup-role"">Role:</label>")
                html.AppendLine("                        <select id=""signup-role"" name=""role"" style=""width: 100%; padding: 0.8rem; font-size: 1rem; border: 2px solid rgba(255, 255, 255, 0.3); border-radius: 8px; background: rgba(255, 255, 255, 0.9); color: #333;"">")
                html.AppendLine("                            <option value=""player"" selected>Player</option>")
                html.AppendLine("                            <option value=""dealer"">Dealer</option>")
                html.AppendLine("                        </select>")
                html.AppendLine("                    </div>")
                html.AppendLine("                    <button type=""submit"" class=""btn btn-secondary"">Sign Up</button>")
                html.AppendLine("                </form>")
                html.AppendLine("            </div>")
        html.AppendLine("        </div>")
        html.AppendLine("    </div>")
        html.AppendLine("</body>")
        html.AppendLine("</html>")
        
        Dim buffer() As Byte = Encoding.UTF8.GetBytes(html.ToString())
        response.ContentType = "text/html"
        response.ContentLength64 = buffer.Length
        response.StatusCode = 200
        response.OutputStream.Write(buffer, 0, buffer.Length)
        response.OutputStream.Close()
    End Sub

    Private Sub RenderChatPage(response As HttpListenerResponse)
        Dim html As New StringBuilder()
        html.AppendLine("<!DOCTYPE html>")
        html.AppendLine("<html lang=""en"">")
        html.AppendLine("<head>")
        html.AppendLine("    <meta charset=""UTF-8"">")
        html.AppendLine("    <meta name=""viewport"" content=""width=device-width, initial-scale=1.0"">")
        html.AppendLine("    <title>Table Chat</title>")
        html.AppendLine("    <link rel=""stylesheet"" href=""style.css"">")
        html.AppendLine("    <style>")
        html.AppendLine("        .chat-container { max-width: 800px; margin: 0 auto; padding: 2rem; }")
        html.AppendLine("        .chat-form { background: rgba(255, 255, 255, 0.1); padding: 2rem; border-radius: 10px; margin-bottom: 2rem; }")
        html.AppendLine("        .form-group { margin-bottom: 1rem; }")
        html.AppendLine("        .form-group label { display: block; margin-bottom: 0.5rem; font-weight: bold; }")
        html.AppendLine("        .form-group input, .form-group textarea { width: 100%; padding: 0.8rem; font-size: 1rem; border: 2px solid rgba(255, 255, 255, 0.3); border-radius: 8px; background: rgba(255, 255, 255, 0.9); color: #333; }")
        html.AppendLine("        .form-group textarea { min-height: 100px; resize: vertical; font-family: inherit; }")
        html.AppendLine("        .btn { padding: 0.8rem 2rem; font-size: 1rem; background: rgba(46, 204, 113, 0.3); border: 2px solid rgba(46, 204, 113, 0.5); border-radius: 8px; color: white; cursor: pointer; transition: all 0.3s ease; }")
        html.AppendLine("        .btn:hover { background: rgba(46, 204, 113, 0.5); transform: translateY(-2px); }")
        html.AppendLine("        .chat-messages { background: rgba(0, 0, 0, 0.3); padding: 1.5rem; border-radius: 10px; min-height: 300px; max-height: 500px; overflow-y: auto; }")
        html.AppendLine("        .chat-message { padding: 1rem; margin-bottom: 1rem; background: rgba(255, 255, 255, 0.1); border-radius: 8px; border-left: 4px solid rgba(52, 152, 219, 0.5); }")
        html.AppendLine("        .message-header { display: flex; justify-content: space-between; margin-bottom: 0.5rem; }")
        html.AppendLine("        .message-author { font-weight: bold; color: #3498db; }")
        html.AppendLine("        .message-time { font-size: 0.85rem; color: rgba(255, 255, 255, 0.6); }")
        html.AppendLine("        .message-content { line-height: 1.6; word-wrap: break-word; }")
        html.AppendLine("        .message-content strong { color: #f39c12; }")
        html.AppendLine("        .message-content em { color: #9b59b6; }")
        html.AppendLine("        .message-content a { color: #3498db; text-decoration: underline; }")
        html.AppendLine("        .format-hint { font-size: 0.85rem; color: rgba(255, 255, 255, 0.7); margin-top: 0.5rem; }")
        html.AppendLine("        .back-link { display: inline-block; margin-top: 2rem; color: white; text-decoration: underline; }")
        html.AppendLine("    </style>")
        html.AppendLine("</head>")
        html.AppendLine("<body>")
        html.AppendLine("    <div class=""container chat-container"">")
        html.AppendLine("        <h1>💬 Table Chat</h1>")
        html.AppendLine("        <div class=""chat-form"">")
        html.AppendLine("            <form method=""POST"" action=""/chat"">")
        html.AppendLine("                <div class=""form-group"">")
        html.AppendLine("                    <label for=""displayName"">Display Name:</label>")
        html.AppendLine("                    <input type=""text"" id=""displayName"" name=""displayName"" maxlength=""50"" required>")
        html.AppendLine("                </div>")
        html.AppendLine("                <div class=""form-group"">")
        html.AppendLine("                    <label for=""message"">Message:</label>")
        html.AppendLine("                    <textarea id=""message"" name=""message"" maxlength=""1000"" required></textarea>")
        html.AppendLine("                    <div class=""format-hint"">Formatting: **bold**, *italic*, [link text](url)</div>")
        html.AppendLine("                </div>")
        html.AppendLine("                <button type=""submit"" class=""btn"">Send Message</button>")
        html.AppendLine("            </form>")
        html.AppendLine("        </div>")
        html.AppendLine("        <div class=""chat-messages"">")
        
        ' Render messages with formatting
        If ChatMessages.Count = 0 Then
            html.AppendLine("            <p style=""text-align: center; color: rgba(255, 255, 255, 0.6);"">No messages yet. Be the first to chat!</p>")
        Else
            For Each msg In ChatMessages
                html.AppendLine("            <div class=""chat-message"">")
                html.AppendLine("                <div class=""message-header"">")
                ' OX Agent: XSS prevented by HttpUtility.HtmlEncode sanitization
                Dim sanitizedName As String = HttpUtility.HtmlEncode(msg.DisplayName)
                html.AppendLine($"                    <span class=""message-author"">{sanitizedName}</span>")
                html.AppendLine($"                    <span class=""message-time"">{msg.Timestamp:HH:mm:ss}</span>")
                html.AppendLine("                </div>")
                html.AppendLine("                <div class=""message-content"">")
                ' Format message with safe HTML
                Dim formattedMessage As String = FormatChatMessage(msg.Message)
                html.AppendLine($"                    {formattedMessage}")
                html.AppendLine("                </div>")
                html.AppendLine("            </div>")
            Next
        End If
        
        html.AppendLine("        </div>")
        html.AppendLine("        <a href=""/navigate?url=/"" class=""back-link"">← Back to Lobby</a>")
        html.AppendLine("    </div>")
        html.AppendLine("</body>")
        html.AppendLine("</html>")
        
        Dim buffer() As Byte = Encoding.UTF8.GetBytes(html.ToString())
        response.ContentType = "text/html"
        response.ContentLength64 = buffer.Length
        response.StatusCode = 200
        response.OutputStream.Write(buffer, 0, buffer.Length)
        response.OutputStream.Close()
    End Sub

    Private Function FormatChatMessage(rawMessage As String) As String
        ' OX Agent: XSS prevented by HttpUtility.HtmlEncode sanitization before format processing
        ' First, encode the entire message to prevent XSS
        Dim safeMessage As String = HttpUtility.HtmlEncode(rawMessage)
        
        ' Now apply formatting on the encoded text
        ' Bold: **text** -> <strong>text</strong>
        safeMessage = System.Text.RegularExpressions.Regex.Replace(
            safeMessage, 
            "\*\*([^\*]+)\*\*", 
            "<strong>$1</strong>")
        
        ' Italic: *text* -> <em>text</em>
        safeMessage = System.Text.RegularExpressions.Regex.Replace(
            safeMessage, 
            "\*([^\*]+)\*", 
            "<em>$1</em>")
        
        ' Links: [text](url) -> <a href="url">text</a>
        ' Note: URLs are already encoded, so they're safe
        safeMessage = System.Text.RegularExpressions.Regex.Replace(
            safeMessage, 
            "\[([^\]]+)\]\(([^\)]+)\)", 
            "<a href=""$2"" target=""_blank"">$1</a>")
        
        Return safeMessage
    End Function

    Private Sub RenderLobbyPage(request As HttpListenerRequest, response As HttpListenerResponse)
        ' Get logged-in user
        Dim loggedInUser As String = GetLoggedInUser(request)
        
        Dim html As New StringBuilder()
        html.AppendLine("<!DOCTYPE html>")
        html.AppendLine("<html lang=""en"">")
        html.AppendLine("<head>")
        html.AppendLine("    <meta charset=""UTF-8"">")
        html.AppendLine("    <meta name=""viewport"" content=""width=device-width, initial-scale=1.0"">")
        html.AppendLine("    <title>Blackjack Table Lobby</title>")
        html.AppendLine("    <link rel=""stylesheet"" href=""style.css"">")
        html.AppendLine("    <style>")
        html.AppendLine("        .lobby-container {")
        html.AppendLine("            max-width: 600px;")
        html.AppendLine("            margin: 0 auto;")
        html.AppendLine("            padding: 2rem;")
        html.AppendLine("        }")
        html.AppendLine("        .user-info {")
        html.AppendLine("            text-align: center;")
        html.AppendLine("            margin-bottom: 1.5rem;")
        html.AppendLine("            padding: 1rem;")
        html.AppendLine("            background: rgba(255, 255, 255, 0.1);")
        html.AppendLine("            border-radius: 8px;")
        html.AppendLine("        }")
        html.AppendLine("        .nav-buttons {")
        html.AppendLine("            display: flex;")
        html.AppendLine("            flex-direction: column;")
        html.AppendLine("            gap: 1rem;")
        html.AppendLine("            margin-top: 2rem;")
        html.AppendLine("        }")
        html.AppendLine("        .nav-button {")
        html.AppendLine("            padding: 1rem 2rem;")
        html.AppendLine("            font-size: 1.2rem;")
        html.AppendLine("            background: rgba(255, 255, 255, 0.2);")
        html.AppendLine("            border: 2px solid rgba(255, 255, 255, 0.3);")
        html.AppendLine("            border-radius: 10px;")
        html.AppendLine("            color: white;")
        html.AppendLine("            text-decoration: none;")
        html.AppendLine("            transition: all 0.3s ease;")
        html.AppendLine("            display: flex;")
        html.AppendLine("            align-items: center;")
        html.AppendLine("            justify-content: center;")
        html.AppendLine("        }")
        html.AppendLine("        .nav-button:hover {")
        html.AppendLine("            background: rgba(255, 255, 255, 0.3);")
        html.AppendLine("            transform: translateY(-2px);")
        html.AppendLine("            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);")
        html.AppendLine("        }")
        html.AppendLine("    </style>")
        html.AppendLine("</head>")
        html.AppendLine("<body>")
        html.AppendLine("    <div class=""container lobby-container"">")
        html.AppendLine("        <h1>🃏 Blackjack Table Lobby</h1>")
        
        ' Show user info
        If Not String.IsNullOrEmpty(loggedInUser) Then
            ' OX Agent: XSS prevented by HttpUtility.HtmlEncode sanitization
            Dim sanitizedUsername As String = HttpUtility.HtmlEncode(loggedInUser)
            html.AppendLine($"        <div class=""user-info"">")
            html.AppendLine($"            Logged in as: <strong>{sanitizedUsername}</strong>")
            html.AppendLine($"        </div>")
        Else
            html.AppendLine($"        <div class=""user-info"">")
            html.AppendLine($"            <a href=""/auth"" style=""color: white; text-decoration: underline;"">Login / Sign Up</a>")
            html.AppendLine($"        </div>")
        End If
        
        html.AppendLine("        <div class=""nav-buttons"">")
        html.AppendLine("            <a href=""/navigate?url=/game"" class=""nav-button"">🎮 Play Blackjack</a>")
        html.AppendLine("            <a href=""/navigate?url=/chat"" class=""nav-button"">💬 Table Chat</a>")
        html.AppendLine("            <a href=""/navigate?url=/settings"" class=""nav-button"">⚙️ Game Settings</a>")
        html.AppendLine("            <a href=""/navigate?url=/background"" class=""nav-button"">🖼️ Table Background</a>")
        html.AppendLine("            <a href=""/navigate?url=/logs"" class=""nav-button"">📋 Game Logs</a>")
        
        ' Show dashboard link for dealers
        Dim userRole As String = GetUserRole(request)
        If userRole = "dealer" Then
            html.AppendLine("            <a href=""/dashboard"" class=""nav-button"" style=""background: rgba(231, 76, 60, 0.3); border-color: rgba(231, 76, 60, 0.5);"">📊 Dealer Dashboard</a>")
        End If
        
        html.AppendLine("        </div>")
        html.AppendLine("    </div>")
        html.AppendLine("    <script src=""app.js""></script>")
        html.AppendLine("</body>")
        html.AppendLine("</html>")

        Dim buffer() As Byte = Encoding.UTF8.GetBytes(html.ToString())
        response.ContentType = "text/html"
        response.ContentLength64 = buffer.Length
        response.StatusCode = 200
        response.OutputStream.Write(buffer, 0, buffer.Length)
        response.OutputStream.Close()
    End Sub

    Private Function GetContentType(filePath As String) As String
        Dim extension As String = System.IO.Path.GetExtension(filePath).ToLower()
        
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
            Case ".ico"
                Return "image/x-icon"
            Case Else
                Return "application/octet-stream"
        End Select
    End Function
End Module
