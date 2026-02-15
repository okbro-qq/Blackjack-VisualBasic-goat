# Blackjack Table Demo

A simple web application demonstrating VB.NET backend with HttpListener and vanilla JavaScript frontend.

## Project Structure

```
.
├── BlackjackTable.vbproj   # Project file
├── Program.vb              # Main server logic with HttpListener
├── wwwroot/                # Static files directory
│   ├── index.html          # Main HTML page
│   ├── style.css           # Styles
│   └── app.js              # Client-side JavaScript
└── README.md               # This file
```

## Requirements

- .NET 8.0 SDK or later

## How to Use

### Testing the Application

1. **Restore dependencies and build:**
   ```bash
   dotnet build
   ```

2. **Run the application:**
   ```bash
   dotnet run
   ```

3. **Access the application:**
   - Open your browser and navigate to: `http://localhost:3000/`

4. **Test Authentication:**
   - Use pre-initialized accounts:
     - **Dealer account**: username `dealer`, password `dealer123`
     - **Player account**: username `player`, password `player123`
   - Or create your own account via Sign Up

5. **Test Dealer Dashboard:**
   - Login with the dealer account
   - Click "Dealer Dashboard" from the lobby
   - View game statistics and system info

6. **Stop the server:**
   - Press `Ctrl+C` in the terminal

## Features

### Current Implementation

- ✅ HttpListener server running on `http://localhost:3000/`
- ✅ Serves static files from `wwwroot/` directory
- ✅ **Authentication System** - Secure signup and login
  - GET `/auth` - Login and signup forms with role selection
  - POST `/signup` - User registration with BCrypt password hashing
  - POST `/login` - Credential verification with secure cookies
  - In-memory user storage
  - Password requirements (minimum 8 characters)
  - Secure cookie configuration (HttpOnly, SameSite=Strict)
  - Role-based access (player or dealer)
  - Lobby displays logged-in username
  - Test accounts pre-initialized:
    - `dealer/dealer123` (role: dealer)
    - `player/player123` (role: player)
- ✅ **Dealer Dashboard** - Role-based statistics page
  - GET `/dashboard` - Restricted to dealers only
  - Shows game statistics:
    - Total hands dealt
    - Player wins vs dealer wins
    - Push count
    - Win percentages
    - User and message counts
  - Access control based on cookie role
  - Dashboard link visible in lobby for dealers only
- ✅ **Lobby page** at root (`/`) with navigation buttons
- ✅ **Centralized navigation** through `/navigate` route with path allowlist validation
- ✅ **Blackjack Game** - Fully playable blackjack with client-side logic
  - Deal, Hit, and Stand buttons
  - Visual card display with suits and values
  - Automatic dealer AI (draws to 17)
  - Win/Lose/Push detection
  - Ace handling (counts as 1 or 11)
  - Proper blackjack rules implementation
- ✅ **Game Settings** - Load configuration presets
  - Text input and preset buttons for config selection
  - Secure config file loading from `configs/` directory
  - Three preset configurations: Standard, Vegas, Tournament
  - JSON display of loaded configurations
  - Path traversal protection with allowlist validation
- ✅ **Table Chat** - Real-time messaging with rich formatting
  - POST `/chat` to send messages
  - GET `/chat/history` for JSON message history
  - Display name and message input
  - Support for simple formatting:
    - **Bold** with `**asterisks**`
    - *Italic* with `*single asterisks*`
    - [Links](url) with `[text](url)` syntax
  - XSS protection with encoding before formatting
  - In-memory message storage
  - Timestamped messages
- ✅ **Table Background** - Custom image preview with proxy
  - Image URL input with preview functionality
  - Server-side image proxy at `/background/proxy`
  - SSRF protection with domain allowlist (Unsplash, Pixabay, Imgur, Picsum)
  - HTTPS-only enforcement
  - Content-Type validation with allowlist
  - Async image fetching with HttpClient
  - 10-second timeout protection
- ✅ One additional placeholder page: Logs
- ✅ Proper content-type headers for different file types
- ✅ Basic error handling and 404 responses
- ✅ **Security**: 
  - Password hashing with BCrypt (work factor 12)
  - Secure cookie configuration (HttpOnly, SameSite=Strict, 1-hour expiration)
  - Open redirect prevention with path allowlist
  - Path traversal prevention with `Path.GetFileName()` and allowlist validation
  - XSS prevention with `HttpUtility.HtmlEncode()` sanitization
  - SSRF prevention with domain allowlist validation
  - Header injection prevention with inline allowlist validation
  - Content Security Policy (CSP) headers on interactive pages
  - Safe message formatting (encode first, then format)
  - Generic error messages to prevent username enumeration

## Navigation

All navigation goes through the `/navigate` route which validates URLs against an allowlist before redirecting:
- `/navigate?url=/game` → Game page
- `/navigate?url=/chat` → Chat page
- `/navigate?url=/settings` → Card themes settings
- `/navigate?url=/background` → Background settings
- `/navigate?url=/logs` → Game logs

This centralized approach prevents open redirect vulnerabilities.

## Next Steps

Future iterations can add:
- Blackjack game logic
- API endpoints for game actions (hit, stand, deal)
- In-memory game state management
- Real-time game updates
