# cb-passivetotal-connector
This tool investigate anomalies on Carbon Black EDR using RiskIQ PassiveTotal public IoCs.

Installation
-

1. Install Python 3 and PIP
2. Clone this repository
3. Go inside the repository and install the requirements: 
```console
pip install -r requirements.txt
```
4. Login https://community.riskiq.com and obtain api key.
5. Finally, build the config file using the api key. 
(Please check out PassiveTotal guide: https://passivetotal.readthedocs.io/en/latest/getting-started.html#install-the-passivetotal-library)


How it works ?
-
First, it connects to the PassiveTotal service and pulls up to date threat reports. It processes the public IoCs found in the docs and translates it into a Carbon Black query. Finally, it searches for IoCs on the EDR and presents the results to the user in "csv" format.

Usage
-
1. Url, port, and Carbon Black API Key fields must be entered in the config file.
2. Config file and script must be in the same directory. Then the script can be run as follows:
```console
python3 cb-passivetotal-connector.py
```
3. After the script runs, it will generate the results as ".csv" in the directory where it is located.

Carbon Black Config File Example
-
<pre>
[APIKEY]
API_KEY = apikey
[URL]
CB_URL = https://1.1.1.1
CB_PORT = 80
</pre>

References
-
1. https://developer.carbonblack.com/reference/enterprise-response/6.3/rest-api/
2. https://pypi.org/project/passivetotal/
3. https://passivetotal.readthedocs.io/en/latest/getting-started.html#install-the-passivetotal-library
