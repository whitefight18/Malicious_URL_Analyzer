# Malicious URL Analyzer
A tool written in python to detect the hostility or suspiciousness of a target URL, utilising IPQualityScore API.  

![GitHub top language](https://img.shields.io/github/languages/top/whitefight18/Malicious_URL_Analyzer?style=flat-square&logo=python&logoColor=lightblue)  ![GitHub](https://img.shields.io/github/license/whitefight18/Malicious_URL_Analyzer?color=gree&style=flat-square)

## Requirements:

`Terminal/Any CLI` for using this tool.  

`python3` from [python.org](https://www.python.org/downloads/)  

`requests` library ( install using `pip3 install requests` )  

`validators` library ( install using `pip3 install validators` )  

IPQualityScore API Key from their website. Register and get it from [IPQualityScore](https://www.ipqualityscore.com/create-account).
Then bind your API Key in the configuration file - `malurlscanner.conf`

## Usage:

Help:

`python3 mal_url_analyzer.py -h`  

To analyze your target URL:  

`python3 mal_url_analyzer.py -u <YOUR_TARGET_URL>`  

To specify the configuration file, if located somewhere else:  

`python3 mal_url_analyzer.py -u <YOUR_TARGET_URL> -c path/to/malurlscanner.conf`  
  
<br>

### Credits:

Big Thanks to IPQualityScore for providing their API. Check them out [here](https://www.ipqualityscore.com/).  

Shoutout to my team members who helped to build this tool -
 - [Hrisikesh Pal](https://github.com/viruszzhkp/)
 - [Chiranjiv Chetia](https://github.com/chiranjiv11/)
 - [Jit Sarkar](https://github.com/sarkarjit/)
 - [Biplab Chattaraj](https://www.instagram.com/biplab_avi/)
