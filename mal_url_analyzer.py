import requests
import json
import sys
from urllib.parse import quote_plus
from validators import ValidationFailure, url as validate_url
from typing import Dict, List
from argparse     import ArgumentParser
from configparser import ConfigParser

# Configuration File
CONFIG_FILE = 'malurlscanner.conf'

# Main Engine
class susURL:
    def __init__(self, apikey: str, strictness: int=0) -> None:
        self.apikey = apikey
        self.strictness = strictness
        self.results = {}

    def fetch(self, url: str) -> None:
        if not self._is_valid_url(url):
            self.results = self._no_results(404, f"URL is Invalid: {url}")
            return

        # API MAGIC
        BASE = 'https://www.ipqualityscore.com/api/json/url'
        encoded_url = quote_plus(url)
        api_url = f'{BASE}/{self.apikey}/{encoded_url}?{self.strictness}'

        try:
            response = requests.get(api_url)
            self.results = json.loads(response.content.decode('utf-8'))
            req = 'You have exceeded your request quota from IP Quality Score API.'
            msg = self.message()
            if not self.success() and req in msg:
                self.results = self._no_results(402, msg)
        except requests.exceptions.ConnectionError:
            msg = "Failed to establish connection to IP Quality Score API."
            self.results = self._no_results(503, msg)

    # Prints the Header
    def print(self, res: bool=False) -> None:
        domain = self.domain()
        header = f'{"*" * len(domain)}\n{domain}\n{"*" * len(domain)}'

        if not self.success():
            print(header)
            print(f'message: {self.message()}')
            print(f'status:  {self.status_code()}')
            return
        output = header
        output += f'\n\nIP Address:     {self.ip_address()}\n'
        output += f'Server Info:    {self.server()}\n'
        output += f'Suspicious:     {self.suspicious()}\n'
        output += f'Unsafe:         {self.unsafe()}\n'        
        output += f'Malware:        {self.malware()}\n'
        output += f'Phishing:       {self.phishing()}\n'
        output += f'Spamming:       {self.spamming()}\n'                
        output += f'Category:       {self.category()}\n'
        output += f'Risk score:     {self.risk_score()}'
        
        self._print(output)

    # Outputs domain name of final destination URL as string
    def domain(self) -> str:
        return self.results.get('domain', '')

    # Outputs IP address of the target domain server as string
    def ip_address(self) -> str:
        return self.results.get('ip_address', '')
    
    # Outputs server info of the target domain as string
    def server(self) -> str:
        return self.results.get('server', NA)
    
    # Outputs boolean value if the domain is suspected of being malicious
    def suspicious(self) -> bool:
        return bool(self.results.get('suspicious'))

    # Outputs boolean value if the domain is suspected of being unsafe
    def unsafe(self) -> bool:
        return bool(self.results.get('unsafe'))
    
    # Outputs boolean value if the domain is associated with viruses or malware
    def malware(self) -> bool:
        return bool(self.results.get('malware'))
    
    # Outputs boolean value if the domain is associated with phishing activities
    def phishing(self) -> bool:
        return bool(self.results.get('phishing'))
        
    # Outputs boolean value if the domain is associated with spam or abusive activities
    def spamming(self) -> bool:
        return bool(self.results.get('spamming'))

    # Outputs category specification amongst 70+ categorisation available from IPQualityScore as string
    def category(self) -> str:
        return self.results.get('category', NA)

    # Outputs a confidence score determining the confidence level for malicious URL detection as integer
    def risk_score(self) -> int:
        return self.results.get('risk_score', DOES_NOT_EXIST)

    # Outputs HTTP status code of the target URL's response as integer
    def status_code(self) -> int:
        return self.results.get('status_code', 0)

    # Outputs typical status message being success or other errors as string
    def message(self) -> str:
        return self.results.get('message', '')
    
    # Outputs boolean value of IPQualityScore request status as successful
    def success(self) -> bool:
        return bool(self.results.get('success'))
    
    # Outputs unique identifier of the request as string
    def request_id(self) -> str:
        return self.results.get('request_id', '')
    
    # Outputs list of errors occurred while making the request as string(s)
    def errors(self) -> List[str]:
        return self.results.get('errors', [])

    def _is_valid_url(self, url: str) -> bool:
        is_valid = validate_url(url)

        if isinstance(is_valid, ValidationFailure):
            return False

        return is_valid

    def _no_results(self, status_code: int, message: str) -> Dict[str, object]:
        return {
            "success": False,
            "message": message,
            "status_code": status_code
        }

def get_args():
    parser = ArgumentParser()
    parser.add_argument('-c', dest='conf_filepath',   help="File path to 'malurlscanner.conf' configuration file.",default=CONFIG_FILE)
    parser.add_argument('-u', dest='url',             help='Target URL link to analyze. eg: https://www.example.com ',required=False)

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    return parser.parse_args()

def print_and_exit(msg):
    print(msg)
    sys.exit(0)

def read_config_file(filename):
    config = ConfigParser()
    config.read(filename)
    return config

def get_data(config):
    cfg = config['malurlscanner']
    apikey = cfg['apikey']
    strictness = cfg['strictness']
    return susURL(apikey, strictness)

def print_results(malurl, urls, res_print):
    for url in urls:
        malurl.fetch(url)
        malurl.print(res_print)
        print('\n')

def main():
    optns = get_args()

    if not optns.url:
        msg = f"Error: No URL provided.\nFor help, run:  'python3 {sys.argv[0]} --help'"
        print_and_exit(msg)

    config_file = optns.conf_filepath

    try:
        config = read_config_file(config_file)
        urls = [optns.url]

        if not urls:
            print_and_exit("Error: No urls specified.")

        malurl = get_data(config)

        print(f"""

___  ___      _ _      _                 _   _______ _       ___              _                    
|  \/  |     | (_)    (_)               | | | | ___ \ |     / _ \            | |                   
| .  . | __ _| |_  ___ _  ___  _   _ ___| | | | |_/ / |    / /_\ \_ __   __ _| |_   _ _______ _ __ 
| |\/| |/ _` | | |/ __| |/ _ \| | | / __| | | |    /| |    |  _  | '_ \ / _` | | | | |_  / _ \ '__|
| |  | | (_| | | | (__| | (_) | |_| \__ \ |_| | |\ \| |____| | | | | | | (_| | | |_| |/ /  __/ |   
\_|  |_/\__,_|_|_|\___|_|\___/ \__,_|___/\___/\_| \_\_____/\_| |_/_| |_|\__,_|_|\__, /___\___|_|   
*********************************************************************************__/ |*************
                                                                                |___/              
                                            v1.0.5 
                            Github : https://github.com/whitefight18

""")

        print_results(malurl, urls, optns)
        print(f"""***  To Be Noted  ***

Risk Scores >= 75 - suspicious - usually due to patterns associated with malicious links.
Risk Scores >= 85 - high risk - strong confidence the URL is malicious.
Risk Scores = 100 AND Phishing = "true" OR Malware = "true" - indicates confirmed malware or phishing activity in the past 24-48 hours.

Suspicious URLs marked with Suspicious = "true" will indicate domains with a high chance for being involved in abusive behavior.
""")

    except KeyError as e:
        print(f"Error: {e.args[0]} section missing from config file '{config_file}'.")
    except FileNotFoundError as e:
        print(e)

if __name__ == '__main__':
    main()