from flask import Flask, request
from urllib3.util.url import parse_url
from bs4 import BeautifulSoup
import re
import requests


ALLOWED_HOSTS = ["google.com", "checkmarx.com"]

app = Flask(__name__)

@app.route('/')
def proxy():
        
        url = request.args.get('url')

        
        # CVE-2020-7212 - parse_url() -> _encode_invalid_chars()
        # CVE-2021-33503 - parse_url()
        host = parse_url(url).host
        
        if host not in ALLOWED_HOSTS:
                return "Not allowed"


        r = requests.get(url)
 
        soup = BeautifulSoup(r.text, 'html.parser')
        
        to_change = soup.find_all(text = re.compile('o'))
        
        for element in to_change:
            fixed_text = element.replace('o', 'O')
            element.replace_with(fixed_text)
            
        return str(soup)

    

if __name__ == '__main__':
        app.run(port=8080)
