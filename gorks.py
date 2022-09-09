import argparse
import json
import re
import requests
import random
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import progressbar

from os.path import exists
from time import sleep
from colorama import Fore
from colorama import Style
from typing import (
    Dict,
    List,
    Optional,
    Any,
    Tuple
)

progressbar.streams.wrap_stderr()


DORK_TRANSFORMS = {
    'Find Microsoft Lync Server AutoDiscover': 'allinurl:XFrame.html',
    'File contains Sensitive Information': '"index of" "*.usernames.txt"',
    'Sensitive Dork Exposing Uploads and Transcation details': 'intext:"index of" "upi" "wp-content"',
    'Pages Containing Login Portal into Various Web Server': 'inurl:"/index.php?route=account/password"',
    'Google to wordpress': 'intitle:"index of" "wp-config.php.bak"'
}

DORK_REGEX = {
    "site:\.[^ ]+": "",
    "site:gov[^ ]*": "",
}

USELESS_DORKS = (
    'index.of.etc',
    '"Search | Invite | Mail | Blog | Forum"',
    'index.of.private',
    'intext: intext: intext: intext: intext:',
)

EXTRA_DORKS = [
    {
        "dork": 'inurl:"/.git"',
        "description": "Search for .git folders"
    },
    {
        "dork": 'ext:bkf | ext:bkp | ext:bak | ext:old | ext:backup',
        "description": "Search for backups"
    },
    {
        "dork": 'ext:doc | ext:docx | ext:odt | ext:pdf | ext:rtf | ext:sxw | ext:psw | ext:ppt | ext:pptx | ext:pps | ext:csv',
        "description": "Search for backups"
    },
    {
        "dork": 'not for distribution | confidential | "employee only" | proprietary | top secret | classified | trade secret | internal | private filetype:xls OR filetype:csv OR filetype:doc OR filetype:pdf',
        "description": "Confidential files"
    },
    {
        "dork": 'ext:doc | ext:docx | ext:odt | ext:pdf | ext:rtf | ext:sxw | ext:psw | ext:ppt | ext:pptx | ext:pps | ext:csv',
        "description": "Search for backups"
    },
    {
        "dork": 'ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:env | ext:ini',
        "description": "Search for config files"
    },
    {
        "dork": 'ext:sql | ext:dbf | ext:mdb',
        "description": "Search for db files"
    },
    {
        "dork": 'intitle:index.of | ext:log | ext:php intitle:phpinfo "published by the PHP Group" | inurl:shell | inurl:backdoor | inurl:wso | inurl:cmd | shadow | passwd | boot.ini | inurl:backdoor | inurl:readme | inurl:license | inurl:install | inurl:setup | inurl:config | inurl:"/phpinfo.php" | inurl:".htaccess" | ext:swf',
        "description": "Other interesting files"
    },
    {
        "dork": 'intext:"sql syntax near" | intext:"syntax error has occurred" | intext:"incorrect syntax near" | intext:"unexpected end of SQL command" | intext:"Warning: mysql_connect()" | intext:"Warning: mysql_query()" | intext:"Warning: pg_connect()"',
        "description": "Search for sql errors"
    },
    {
        "dork": 'intext:"sql syntax near" | intext:"syntax error has occurred" | intext:"incorrect syntax near" | intext:"unexpected end of SQL command" | intext:"Warning: mysql_connect()" | intext:"Warning: mysql_query()" | intext:"Warning: pg_connect()"',
        "description": "Search for sql errors"
    },
    {
        "dork": '"PHP Parse error" | "PHP Warning" | "PHP Error"',
        "description": "Search for php errors"
    },
    {
        "dork": '"PHP Parse error" | "PHP Warning" | "PHP Error"',
        "description": "Search for php errors"
    },
    {
        "dork": 'inurl:wp-content | inurl:wp-includes',
        "description": "Search for wordpress files"
    },
    {
        "dork": 'inurl:signup | inurl:register | intitle:Signup',
        "description": "Login pages"
    },
    {
        "dork": 'intitle:traefik inurl:8080/dashboard',
        "description": "Traefik"
    },
    {
        "dork": 'intitle:traefik inurl:8080/dashboard',
        "description": "Traefik"
    },
    {
        "dork": 'intitle:traefik inurl:8080/dashboard',
        "description": "Traefik"
    },
    {
        "dork": 'intitle:"Dashboard [Jenkins]"',
        "description": "Jenkins"
    },
    {
        "dork": 'inurl:redir | inurl:url | inurl:redirect | inurl:return | inurl:src=http | inurl:r=http',
        "description": "Open Redirects"
    },
    {
        "dork": 'ext:action | ext:struts | ext:do',
        "description": "Apache Struts RCE"
    },
]


# 100 requests per minute and api key, but each request takes some time so lets give some extra 100
RATE_LIMIT_SLEEP = 60/200


def google_search(search_term: str, gcse_id: str, api_key: str, debug:bool, siterestrict:bool, **kwargs) -> Tuple[Optional[Dict[str, Any]], str]:
        """
        Perform a search inside a google custom search engine ID
        """

        sleep(RATE_LIMIT_SLEEP)

        other_args = ""
        if kwargs:
            for key, value in kwargs.items():
                other_args += f"&{key}={value}"

        if siterestrict:
            url = f"https://www.googleapis.com/customsearch/v1/siterestrict?key={api_key}&cx={gcse_id}&q={search_term}{other_args}"
        else:
            url = f"https://www.googleapis.com/customsearch/v1?key={api_key}&cx={gcse_id}&q={search_term}{other_args}"

        if debug:
            print(f"[d] Debug: {url}")

        try:
            res = requests.get(url).json()
        except Exception as e:
            if "Remote end closed connection without" in str(e):
                print("Found 'Remote end closed connection without' error, retrying in 3 secs")
                sleep(3)
                return google_search(search_term=search_term, gcse_id=gcse_id, api_key=api_key, debug=debug, siterestrict=siterestrict, **kwargs)

            else:
                print(f"Error performing request: {e}")
                return None, url

        if "error" in res and "code" in res["error"] and int(res["error"]["code"]) == 429:
            print(f"429 code in google search. Sleeping 10s and retrying. Error: {res['error'].get('message', '')}")
            sleep(10)
            return google_search(search_term=search_term, gcse_id=gcse_id, api_key=api_key, debug=debug, siterestrict=siterestrict, **kwargs)

        total_results = res['searchInformation']['totalResults'] if 'searchInformation' in res and 'totalResults' in res['searchInformation'] else 0
        items = res['items'] if "items" in res else []

        res = {
            "totalResults": total_results,
            "items": items
        }

        return res, url


def req_query(query: str, gcse_id: str, api_key: str, debug: bool, siterestrict:bool, start: int = 1, max_results: int = 20) -> Tuple[Optional[List[Any]], str]:
        """
        Search a query inside a google custom search engine ID and if more results get them
        """

        response, url = google_search(query, gcse_id, api_key, debug, siterestrict, num=10, start=start)

        if not response:
            return None, url

        results = response["items"]
        if int(response["totalResults"]) >= start+10 and start+10 < max_results: # Max of 20 results in total
            results += req_query(query, gcse_id, api_key, debug, siterestrict, start=start+10, max_results=max_results)[0]

        return results, url


def check_dorks(gdork_list_name: str, gdork_list: List[Dict], gcse_id: str, api_key: str, debug:bool, siterestrict:bool, out_json_file:str) -> None:
    print(f"Category: {Fore.GREEN}{gdork_list_name.upper()}{Style.RESET_ALL}!")
    print("")

    json_results = {}

    for i in progressbar.progressbar(range(len(gdork_list))):
        item = gdork_list[i]
        dork = item["dork"]
        description = item["description"].replace("\r","")

        if len(dork) < 10 or dork in USELESS_DORKS:
            continue

        if dork in DORK_TRANSFORMS:
            dork = DORK_TRANSFORMS[dork]
        
        elif re.match(r'index[ \.]of[ \.][\w/_\-]+$', dork):
            dork = '"%s"' % dork
        
        for regex, replacement in DORK_REGEX.items():
            dork = re.sub(regex, replacement, dork)

        if debug:
            print(f"[d] Debug: {dork}")
        results, url = req_query(dork, gcse_id, api_key, debug, siterestrict)

        if not results:
            continue
        
        # If here, something was found
        json_results[dork] = {
            "name": dork,
            "category": gdork_list_name,
            "description": description,
            "results": [res["link"] for res in results]
        }
        
        progressbar.streams.flush()
        print("")
        print(f"{Fore.YELLOW}[u] {Fore.BLUE}{url}")
        print(f"{Fore.YELLOW}[+] {Fore.BLUE}Dork: {Style.RESET_ALL}{dork}")
        print(f"{Fore.YELLOW}[?] {Fore.BLUE}Description: {Style.RESET_ALL}{description}")
        print(f"{Fore.YELLOW}[i] {Fore.BLUE}Links:{Style.RESET_ALL}")
        for res in results:
            print(res["link"])

        print("")
    
    print("==================================")
    print("")

    if out_json_file:
        with open(out_json_file, "w") as f:
            json.dump(json_results, f)

def main():
    parser = argparse.ArgumentParser(description='Search google dorks in the specified GCSE id')
    parser.add_argument('--cseid', help='Id of the custom search engine', required=True)
    parser.add_argument('--api-key', help='API key')
    parser.add_argument('--api-keys-file', help='Read api keys from file')
    parser.add_argument('--dorks', help='Path to JSON dorks', required=True)
    parser.add_argument('--debug', help='Debug', default=False, action='store_true')
    parser.add_argument('--siterestrict', help='Use siterestrict api (the engine has less than 10 domains)', default=False, action='store_true')
    parser.add_argument('--json-file', help='Store json results in the indicated file')

    args = parser.parse_args()
    cseid = args.cseid
    apikey_file = args.api_keys_file
    api_key = args.api_key
    dorks_path = args.dorks
    debug = args.debug
    siterestrict = args.siterestrict
    out_json_file = args.json_file

    if not apikey_file and not api_key:
        print("You need to specify a --api.key or --api-keys-file")
        exit(1)

    # Check if path file exists
    if not exists(dorks_path):
        print(f"File {dorks_path} does not exist")
        exit(1)

    # load json from dorks_path
    with open(dorks_path) as json_file:
        dorks_json = json.load(json_file)
    
    
    # Add EXTRA_DORKS to dorks_json
    dorks_json["EXTRA DORKS"] = EXTRA_DORKS
    
    api_keys = []
    if apikey_file:
        with open(apikey_file) as f:
            api_keys = f.read().splitlines()
    
    # If nothing just return as correct execution indicating that no apis were found
    if apikey_file and not api_keys:
        print("No api keys in file")
        exit(0)
    
    # Search each dork
    for dork_list_name, dork_list in dorks_json.items():
        if api_keys:
            api_key = random.choice(api_keys)
        
        check_dorks(dork_list_name, dork_list, cseid, api_key, debug, siterestrict, out_json_file)


if __name__ == "__main__":
    main()

    
"""
Dorks using all Internet (not just the attacked platform), useful for a wider gorks project:
site:trello.com | site:*.atlassian.net "<domain_keyword>" -- Project management
site:*.domain.com -- Subdomains
site:github.com | site:gitlab.com | site:bitbucket.org "phantom" -- Git site
site:.s3.amazonaws.com | site:storage.googleapis.com | site:amazonaws.com "<domain_keyword>" -- Cloud Buckets
intitle:traefik inurl:8080/dashboard "<domain_keyword>" -- traefik
intitle:\"Dashboard [Jenkins]\" "<domain_keyword>" -- Jenkins
site:sharecode.io | site:controlc.com | site:codepad.co |site:ideone.com | site:codebeautify.org | site:jsdelivr.com | site:codeshare.io | site:codepen.io | site:repl.it | site:jsfiddle.net "<domain_keyword>" -- Code share sites
site:gitter.im | site:papaly.com | site:productforums.google.com | site:coggle.it | site:replt.it | site:ycombinator.com | site:libraries.io | site:npm.runkit.com | site:npmjs.com | site:scribd.com "<domain_keyword>" -- Other third party sites
site:stackoverflow.com "<domain>" -- stackoverflow
site:justpaste.it | site:heypasteit.com | site:pastebin.com "<domain_keyword>" -- paste sites
site:linkedin.com employees "<domain>" -- linkeding
"""
