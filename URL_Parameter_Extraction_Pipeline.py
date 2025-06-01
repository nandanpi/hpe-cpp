from sklearn.base import BaseEstimator, TransformerMixin
import pandas as pd
from tqdm import tqdm
from multiprocessing import cpu_count
from multiprocessing.pool import ThreadPool
import re
from urllib.parse import urlparse, parse_qs
import tldextract
import idna
import unicodedata
import ssl
import socket
from datetime import datetime, timezone
import whois
import time
import numpy as np

class URLFeatureExtractor(BaseEstimator, TransformerMixin):
    def __init__(self, num_workers=None):
        self.num_workers = num_workers
        self.columns = [
            # total url related parameters
            'URL_Length', 'Url_Shortening', 'Ssl_Info',
            'Global_Ranking', 'Has_Suspicious_Params', 'Num_Languages',
            # Scheme
            'Uses_HTTPS',
            # User Info
            'Has_User_Info', 'User_Info_Length',
            # Subdomain
            'Num_Subdomains', "Num_Digits_Subdomain", 'Num_Hyphens_Subdomain', 'Length_Subdomain', 
            'Num_Dots_Subdomain', 'Num_Dash_Subdomain',
            'Num_AtSymbol_Subdomain', 'Num_TildeSymbol_Subdomain', 'Num_Underscore_Subdomain', 
            'Num_Percent_Subdomain', 'Num_Ampersand_Subdomain', 'Num_Hash_Subdomain',
            'Hex_Encoded_Characters_Subdomain',
            # Domain
            'Has_Ip', "Num_Digits_Domain", 'Num_Hyphens_Domain', 'Length_Domain', 'Num_Dots_Domain', 
            'Num_Dash_Domain', 'Num_AtSymbol_Domain',
            'Domain_Age', 'Num_TildeSymbol_Domain', 'Num_Underscore_Domain', 'Num_Percent_Domain', 
            'Num_Ampersand_Domain', 'Num_Hash_Domain', 'Hex_Encoded_Characters_Domain',
            # TLD
            'TLD',
            # Port
            'Has_Port',
            # Path
            'Path_Level', "Num_Digits_Path", 'Num_Hyphens_Path', 'Length_Path', 'Num_Dots_Path', 
            'Num_Dash_Path', 'Num_AtSymbol_Path',
            'Num_TildeSymbol_Path', 'Num_Underscore_Path', 'Num_Percent_Path', 'Num_Ampersand_Path', 
            'Num_Hash_Path', 'Num_DoubleSlash_Path',
            'Hex_Encoded_Characters_Path',
            # Query
            "Num_Digits_Query", 'Num_Hyphens_Query', 'Length_Query', 'Num_Query_Params', 'Num_Dots_Query', 
            'Num_Dash_Query', 'Num_AtSymbol_Query',
            'Num_TildeSymbol_Query', 'Num_Underscore_Query', 'Num_Percent_Query', 'Num_Ampersand_Query', 
            'Num_Hash_Query', 'Hex_Encoded_Characters_Query',
            # Fragment
            "Has_Fragment"
        ]
        
        self.suspicious_url_parameters = {
            # Open Redirects & Phishing
            "redirect", "next", "url", "dest", "out", "view", "link", "goto", "target", "forward", "jump",
            # Remote Code Execution (RCE)
            "cmd", "eval", "execute", "exec", "shell", "run", "code", "command", "process", "do",
            # File Inclusion & Download Attacks (LFI & RFI)
            "file", "filepath", "download", "include", "load", "document", "pdf", "attachment",
            "export", "import", "module", "dir", "read", "write", "stream", "content", "getfile",
            # Download-related extensions
            "exe", "msi", "apk", "bat", "sh", "cmd", "jar", "scr", "zip", "rar", "7z", "tar", "gz",
            "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "iso", "img", "vbs", "ps1", "dll", "reg",
            # SQL Injection (SQLi)
            "id", "query", "search", "order", "sort", "filter", "select", "drop", "union", "table",
            "from", "where", "update", "delete", "insert", "fetch", "database", "schema",
            # Authentication Bypass & Session Hijacking
            "token", "session", "auth", "jwt", "sso", "apikey", "password", "pass", "user", "username",
            "email", "key", "credential", "login", "logout", "csrf", "remember", "access", "validate",
            # XSS (Cross-Site Scripting)
            "script", "alert", "onload", "onerror", "onmouseover", "onclick", "onfocus",
            "data", "src", "href", "javascript", "vbscript", "expression", "cookie", "input",
            # Command Injection
            "ping", "nc", "ncat", "curl", "wget", "bash", "sh", "zsh", "perl", "python",
            # Path Traversal & Directory Access
            "path", "dir", "folder", "root", "home", "var", "etc", "passwd", "config", "secret",
            # API & Debugging
            "debug", "test", "trace", "log", "verbose", "info", "error", "status", "diagnostic"
        }
        
        self.IGNORE_CHARACTERS = [
            ".", "-", "_", "~", "/", "?", "#", "&", "=", "%", "@", ":", ";", ",", "+", "*", "!", "$", "'", 
            '"', "(", ")", "[", "]", "{", "}", "|", "\\"
        ]
        
        # Initialize shorteners list (you'll need to provide this)
        self.shortener_domains = eval(open('url_shortener_extensions.txt','r').read())# Initialize with your shortener domains

    def fit(self, X, y=None):
        return self
    
    def transform(self, X):
        """Process a list of URLs and return their features"""
        if isinstance(X, pd.Series):
            urls = X.tolist()
        elif isinstance(X, list):
            urls = X
        else:
            urls = [X]
            
        num_workers = min(self.num_workers or cpu_count(), 8)
        
        with ThreadPool(num_workers) as pool:
            data = list(tqdm(pool.imap(self._process_single_url, urls), total=len(urls), desc="Processing URLs"))
            #print(data)
        # Remove None values (failed URLs)
        data = [entry for entry in data if entry is not None]
        
        # Ensure each row has all expected columns
        features = [{col: entry.get(col, None) for col in self.columns} for entry in data]
        
        return pd.DataFrame(features, columns=self.columns)
    
    def _process_single_url(self, url):
        """Process a single URL and return its features"""
        try:
            features = {}
            features['URL_Length'] = len(url)
            features['Url_Shortening'] = self._is_shortened_url(url)

            parsed = urlparse(url)
            domain_info = tldextract.extract(url)
            domain = f"{domain_info.domain}.{domain_info.suffix}"

            features['Ssl_Info'] = None#self._get_ssl_certificate_info(domain)
            features['Global_Ranking'] = None#self._get_latest_tranco_rank(domain)

            query_params = parsed.query.split("&") if parsed.query else []
            features['Has_Suspicious_Params'] = any(
                param.split("=")[0] in self.suspicious_url_parameters for param in query_params
            )

            features['Num_Languages'] = self._get_num_languages(domain)
            features['Uses_HTTPS'] = 1 if url.startswith("https") else 0
            features['Has_User_Info'], features['User_Info_Length'] = self._get_user_info(url)

            # Process subdomain, domain, path, query features
            features.update(self._process_subdomain(domain_info.subdomain))
            features.update(self._process_domain(domain_info.domain, domain_info.suffix))
            
            features['TLD'] = domain_info.suffix
            features['Has_Port'] = self._has_port(url)
            
            features.update(self._process_path(parsed.path))
            features.update(self._process_query(parsed.query))
            
            features['Has_Fragment'] = self._has_fragment(url)

            return features

        except Exception as e:
            print(f"Error processing {url}: {e}")
            return None
    
    # All the helper methods from your original code go here, prefixed with _
    # For example:
    def _decode_idn(self, domain):
        """Decode multi-layer IDN domains (handles double Punycode encoding)."""
        while True:
            try:
                decoded = idna.decode(domain)
                if decoded == domain:
                    break
                domain = decoded
            except idna.IDNAError:
                break
        return domain
    
    def _get_num_languages(self, domain):
        """Decode domain, identify character scripts, and count unique ones."""
        decoded_domain = self._decode_idn(domain)
        scripts = set()

        for char in decoded_domain:
            if char in self.IGNORE_CHARACTERS:
                continue
            try:
                script_name = unicodedata.name(char).split()[0]
                scripts.add(script_name)
            except ValueError:
                continue
        return len(scripts)
    
    def _analyze_string_metrics(self, input_str):
        """Returns a dictionary with counts of various special characters in the input string."""
        return {
            "Num_Digits": len(re.findall(r"\d", input_str)),
            "Num_Hyphens": input_str.count("-"),
            "Length": len(input_str),
            "Num_Dots": input_str.count("."),
            "Num_Dash": input_str.count("_"),
            "Num_AtSymbol": input_str.count("@"),
            "Num_TildeSymbol": input_str.count("~"),
            "Num_Underscore": input_str.count("_"),
            "Num_Percent": input_str.count("%"),
            "Num_Ampersand": input_str.count("&"),
            "Num_Hash": input_str.count("#"),
            "Hex_Encoded_Characters": len(re.findall(r"%[0-9A-Fa-f]{2}", input_str))
        }
    
    def _process_subdomain(self, subdomain):
        num_subdomains = len([sub for sub in subdomain.split(".") if sub])
        if subdomain.count('.') == 0:
            num_subdomains = 0
            features = self._analyze_string_metrics("")
        else:
            subdomain = '.'.join(subdomain.split('.')[:-1])
            features = self._analyze_string_metrics(subdomain)
        
        features = {f"{key}_Subdomain": value for key, value in features.items()}
        features['Num_Subdomains'] = num_subdomains
        return features
    
    def _process_domain(self, domain, suffix):
        features = self._analyze_string_metrics(domain)
        features = {f"{key}_Domain": value for key, value in features.items()}
        features['Has_Ip'] = bool(re.match(r"\d+\.\d+\.\d+\.\d+", domain))
        # features['Domain_Age'] = self._get_domain_age(domain + '.' + suffix)
        return features
    
    def _process_path(self, path):
        features = self._analyze_string_metrics(path)
        features = {f"{key}_Path": value for key, value in features.items()}
        if path == '':
            features['Path_Level'] = 0
        elif path == '/':
            features['Path_Level'] = 1
        else:
            features['Path_Level'] = path.count('/')
        features['Num_DoubleSlash_Path'] = path.count('//')
        return features
    
    def _process_query(self, query):
        features = self._analyze_string_metrics(query)
        features = {f"{key}_Query": value for key, value in features.items()}
        features['Num_Query_Params'] = len(parse_qs(query))
        return features
    
    def _get_domain_age(self, domain):
        for _ in range(3):
            try:
                domain_info = whois.whois(domain)
                creation_date = domain_info.creation_date

                if isinstance(creation_date, list):
                    creation_date = [
                        d.replace(tzinfo=timezone.utc) if d.tzinfo is None else d.astimezone(timezone.utc)
                        for d in creation_date if isinstance(d, datetime)
                    ]
                    if not creation_date:
                        continue
                    creation_date = min(creation_date)

                if isinstance(creation_date, datetime):
                    if creation_date.tzinfo is None:
                        creation_date = creation_date.replace(tzinfo=timezone.utc)
                    else:
                        creation_date = creation_date.astimezone(timezone.utc)

                    return (datetime.now(timezone.utc) - creation_date).days

            except Exception as e:
                print(f"Lookup failed for {domain}: {e}")
                time.sleep(1)
        return -1
    
    def _get_user_info(self, url):
        parsed_url = urlparse(url)
        username = parsed_url.username or ""
        password = parsed_url.password or ""
        has_user_info = bool(username or password)
        user_info_length = len(username) + len(password)
        return has_user_info, user_info_length
    
    def _is_shortened_url(self, url):
        domain = urlparse(url).netloc.lower()
        return domain in self.shortener_domains
    
    def _has_port(self, url):
        parsed_url = urlparse(url)
        return parsed_url.port is not None
    
    def _get_ssl_certificate_info(self, hostname, port=443):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    if not cert:
                        return 0
                    # ... rest of the SSL validation logic ...
                    return 1
        except ssl.SSLCertVerificationError:
            return 0
        except Exception as e:
            print(f"SSL check error for {hostname}: {e}")
            return -1
    
    def _has_fragment(self, url):
        parsed_url = urlparse(url)
        return bool(parsed_url.fragment)
    
    def _get_latest_tranco_rank(self, domain):
        BASE_URL = "https://tranco-list.eu/api"
        url = f"{BASE_URL}/ranks/domain/{domain}"
        try:
            response = requests.get(url)
            if response.status_code == 200:
                ranks = response.json().get("ranks", [])
                if not ranks:
                    return 0
                ranks.sort(key=lambda x: x["date"], reverse=True)
                return ranks[0]["rank"]
            elif response.status_code in (403, 429):
                return -1
            else:
                return -1
        except Exception:
            return -1


