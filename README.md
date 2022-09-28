# Gorks

![](gorks.jpeg)


**Google Dorks finally made easy to run without hiding.**

## Quick Start

```bash
pip3 install -r requirements
# Use --siterestrict if you have configured less than 10 domains in the cseid
python3 gorks.py --cseid <cseid> --dorks ./ghdb.json [--api-key <api_key>|--api-keys-file </path/apikeys>] [--siterestrict] [--json-file </oath/to/json_file>] 2>/dev/null
```

Create a **Google Custom Search Engine** in https://programmablesearchengine.google.com/, configure the **domain(s)** where you want to search the Dorks in that engine, and **get the ID** and use it in the `--cseid` param.

**Please, note that 1 execution of Gorks over all the google hacking database in GCSE costs around 80$ !!**

Create a **API key for the Custom Search** service in https://console.cloud.google.com/apis/api/customsearch.googleapis.com/metrics

You can **download an updated `ghdb.json`** from https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/ghdb.json

If you like **Gorks** you will probably like also **[Pastos](https://github.com/carlospolop/Pastos)** and **[Leakos](https://github.com/carlospolop/Leakos)**
