# 🎰 Blackjack Table

A live coding demo featuring a blackjack game built with VB.NET backend and vanilla JavaScript frontend.

## Tech Stack

- **Backend**: VB.NET console application with HttpListener
- **Frontend**: Plain HTML, CSS, and vanilla JavaScript
- **Server**: HTTP server on port 3000
- **State**: In-memory (no database)

## Project Structure

```
vb-blackjack-claude/
├── Program.vb              # Single module with all server logic
├── BlackjackTable.vbproj   # VB.NET project file
├── wwwroot/                # Static files
│   ├── index.html          # Main HTML page
│   ├── styles.css          # Styling
│   └── app.js              # Client-side JavaScript
└── README.md               # This file
```

## Prerequisites

- [.NET 8.0 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) or later

## How to Build and Run

1. **Restore dependencies** (if needed):
   ```bash
   dotnet restore
   ```

2. **Build the project**:
   ```bash
   dotnet build
   ```

3. **Run the server**:
   ```bash
   dotnet run
   ```

4. **Open your browser**:
   Navigate to [http://localhost:3000](http://localhost:3000)

5. **Stop the server**:
   Press `Ctrl+C` in the terminal

## Quick Start (One Command)

```bash
dotnet run
```

That's it! The server will start and serve the static files from the `wwwroot/` directory.

## Features (Current)

✓ HttpListener-based HTTP server  
✓ Static file serving from wwwroot/  
✓ Content-type detection  
✓ Clean console logging  
✓ Modern, responsive UI  

## Next Steps

- Add blackjack game logic
- Implement card dealing API
- Add player/dealer hands
- Implement game rules
- Add betting system

## API Endpoints

Currently available:
- `GET /` - Serves index.html
- `GET /styles.css` - Serves CSS
- `GET /app.js` - Serves JavaScript

---

**Note**: This is a development server for demonstration purposes. For production use, consider using ASP.NET Core or similar frameworks.
