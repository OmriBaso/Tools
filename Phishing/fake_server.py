import http.server
import ssl
import os
import json

websites = json.loads(open("website_config.json", "r").read())

# Define a custom handler to serve a specific file on GET request
class CustomHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # Normalize header keys to lowercase
        headers = {k.lower(): v for k, v in self.headers.items()}
        
        # Get the host from the headers (if available)
        host = headers.get("host")
        
        if host:
            # Split the host by dot and get the last two parts (domain and TLD)
            parts = host.split(".")
            if len(parts) >= 2:
                domain_tld = ".".join(parts[-2:])  # Join the last two parts (domain and TLD)
                
                # Check if the domain and TLD exist in the websites dictionary
                if domain_tld in websites:
                    file_path = websites[domain_tld]
                    try:
                        with open(file_path, 'rb') as file:
                            self.send_response(200)
                            self.send_header("Content-type", "text/html")
                            self.end_headers()
                            self.wfile.write(file.read())
                    except FileNotFoundError:
                        self.send_error(404, "File Not Found")
                else:
                    self.send_error(404, "Domain Not Found")
            else:
                self.send_error(400, "Bad Request: Invalid Host Header")
        else:
            self.send_error(400, "Bad Request: Missing Host Header")


# Create the HTTP server, binding it to 0.0.0.0 on port 443
httpd = http.server.HTTPServer(('0.0.0.0', 443), CustomHTTPRequestHandler)

# Wrap the server with 
httpd.socket = ssl.wrap_socket(httpd.socket,
                               keyfile="key.pem",
                               certfile="cert.pem",
                               server_side=True)

# Start the server
print("Serving on https://0.0.0.0:443")
httpd.serve_forever()
