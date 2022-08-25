import argparse
import json
import re
import requests
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


def check_dorks(gdork_list_name: str, gdork_list: List[Dict], gcse_id: str, api_key: str, debug:bool, siterestrict:bool) -> None:
    print(f"Category: {Fore.GREEN}{gdork_list_name.upper()}{Style.RESET_ALL}!")
    print("")

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

def main():
    parser = argparse.ArgumentParser(description='Search google dorks in the specified GCSE id')
    parser.add_argument('--cseid', help='Id of the custom search engine', required=True)
    parser.add_argument('--api-key', help='API key', required=True)
    parser.add_argument('--dorks', help='Path to JSON dorks', required=True)
    parser.add_argument('--debug', help='Debug', default=False, action='store_true')
    parser.add_argument('--siterestrict', help='Use siterestrict api (the engine has less than 10 domains)', default=False, action='store_true')

    args = parser.parse_args()
    csid = args.cseid
    api_key = args.api_key
    dorks_path = args.dorks
    debug = args.debug
    siterestrict = args.siterestrict

    # Check if path file exists
    if not exists(dorks_path):
        print(f"File {dorks_path} does not exist")
        exit(1)

    # load json from dorks_path
    with open(dorks_path) as json_file:
        dorks_json = json.load(json_file)
    
    # Search each dork
    for dork_list_name, dork_list in dorks_json.items():
        check_dorks(dork_list_name, dork_list, csid, api_key, debug, siterestrict)


if __name__ == "__main__":
    main()
