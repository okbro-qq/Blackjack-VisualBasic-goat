#!/usr/bin/env python3
"""
Simple HTTP server to test SSRF vulnerability
Serves an image from the desktop
"""

from http.server import HTTPServer, SimpleHTTPRequestHandler
import os

class ImageHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/image.jpg' or self.path == '/':
            # Serve the image from desktop
            image_path = '/Users/mostafanaamneh/Desktop/efootball-2024-3440x1440-13048.jpg'
            
            try:
                with open(image_path, 'rb') as f:
                    image_data = f.read()
                
                self.send_response(200)
                self.send_header('Content-Type', 'image/jpeg')
                self.send_header('Content-Length', len(image_data))
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(image_data)
                
                print(f"✅ Served image to {self.client_address[0]}")
            except Exception as e:
                self.send_error(404, f"Image not found: {e}")
        else:
            self.send_error(404, "Not found")
    
    def log_message(self, format, *args):
        # Custom logging
        print(f"[REQUEST] {self.client_address[0]} - {format % args}")

def run_server(port=8888):
    server_address = ('', port)
    httpd = HTTPServer(server_address, ImageHandler)
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║           🖼️  SSRF Test Image Server                         ║
╚══════════════════════════════════════════════════════════════╝

Server running at: http://localhost:{port}/
Image URL: http://localhost:{port}/image.jpg

To test SSRF vulnerability, use this in the Blackjack app:
http://localhost:3000/background/proxy?src=http://localhost:{port}/image.jpg

Or visit: http://localhost:3000/background
And enter: http://localhost:{port}/image.jpg

Press Ctrl+C to stop the server...
""")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n\n👋 Server stopped")
        httpd.shutdown()

if __name__ == '__main__':
    run_server()
