#!/usr/bin/python3
# -*- coding: utf-8 -*-


'''
Author      : Oguzcan Pamuk
Date        : 26.10.2021
Description : 
References  :
            -   https://pypi.org/project/passivetotal/
            -   https://passivetotal.readthedocs.io/en/latest/getting-started.html#install-the-passivetotal-library
'''

'''
Requirements: 
    - pip3 install passivetotal,configparser,requests
    - Before using, build a passivetotal config file with API Token.
    - CB API Key
    - CB URL & Port
'''

from passivetotal import analyzer
import requests
import configparser
import sys
import csv
import time


PROGRAM_NAME = '''
  ______ ______     ______                _            _______                _      ______                                             
 / _____|____  \   (_____ \              (_)          (_______)     _        | |    / _____)                            _               
| /      ____)  )__ _____) )___  ___  ___ _ _   _ ____ _       ___ | |_  ____| |___| /      ___  ____  ____   ____ ____| |_  ___   ____ 
| |     |  __  (___)  ____/ _  |/___)/___) | | | / _  ) |     / _ \|  _)/ _  | (___) |     / _ \|  _ \|  _ \ / _  ) ___)  _)/ _ \ / ___)
| \_____| |__)  )  | |   ( ( | |___ |___ | |\ V ( (/ /| |____| |_| | |_( ( | | |   | \____| |_| | | | | | | ( (/ ( (___| |_| |_| | |    
 \______)______/   |_|    \_||_(___/(___/|_| \_/ \____)\______)___/ \___)_||_|_|    \______)___/|_| |_|_| |_|\____)____)\___)___/|_|    
                                                                                                                                        
'''

INDICATOR_TYPES = ["hash_sha256","domain","hash_md5","ip","filename"]
PROCESS_SEARCH_URL = "/api/v1/process?"
QUERY_PARAMETER = "q="
CB_SHA256_HASH = "sha256:"
CB_MD5_HASH = "md5:"
CB_DOMAIN = "domain:"
CB_IP = "ipaddr:"
CB_FILENAME = "filemod:"
SHA_256 = "hash_sha256"
MD5 = "hash_md5"
LEFT_PARETHESIS = ")" 
RIGHT_PARETHESIS = "(" 
OR_OPERATOR = "OR"
IP = "ip"
FILENAME = "filename"
ZERO = 0
OUTPUT_FILENAME = "result_"
EXTENTION = ".csv"
CONFIG_FILE_NAME = "config.ini"
SUCCESS_CODE = 200
UNAUTHORIZED_CODE = 401
LIMIT = 10

def readConfigFile():
    try:
        configParser = configparser.RawConfigParser()
        configFilePath = CONFIG_FILE_NAME
        configParser.read(configFilePath)
        api_key = configParser.get('APIKEY', 'API_KEY')
        url = configParser.get('URL', 'CB_URL')
        port = configParser.get('URL', 'CB_PORT')
    except configparser.NoOptionError as error:
        print ("Error in options Name", error)
        sys.exit()
    except configparser.NoSectionError as error:
        print ("Error in sections Name", error)
        sys.exit()
    except configparser.ParsingError as error:
        print ('Could not parse:', error)

    return api_key,url,port

def indicatorCheck(indicator_type):
    for type in indicator_type:
        if type in INDICATOR_TYPES:
            return True
    return False

def prepareCarbonBlackSearchQuery(indicator):
    query = ""
    ioc_type = str(indicator['type']).strip()

    if ioc_type == SHA_256:
        for hash in (indicator['values']):
            query += RIGHT_PARETHESIS + CB_SHA256_HASH + hash + LEFT_PARETHESIS + " " + OR_OPERATOR + " "
    elif ioc_type == MD5: 
        for hash in (indicator['values']):
            query += RIGHT_PARETHESIS + CB_MD5_HASH + hash + LEFT_PARETHESIS + " " + OR_OPERATOR + " "
    elif ioc_type == "domain":
        for domain in (indicator['values']):
            query += RIGHT_PARETHESIS + CB_DOMAIN + domain + LEFT_PARETHESIS + " " + OR_OPERATOR + " "
    elif ioc_type == IP:
        for ip in (indicator['values']):
            query += RIGHT_PARETHESIS + CB_IP + ip + LEFT_PARETHESIS + " " + OR_OPERATOR + " "
    elif ioc_type == FILENAME:
        for filename in (indicator['values']):
            query += RIGHT_PARETHESIS + CB_FILENAME + filename + LEFT_PARETHESIS + " " + OR_OPERATOR + " "
    else:
        return None

    return query[:-3]

def getArticlesWithIndicators(analyzer):
    articles = analyzer.AllArticles()
    articlesWithIndicators = []
    for article in articles:
        if (article.age<1 and article.indicator_count>ZERO):
            if(indicatorCheck(article.indicator_types)):
                articlesWithIndicators.append(article)
    return articlesWithIndicators

def searchQueryOnCarbonBlack(api_key,url,port,query):
    headers = {'X-Auth-Token':api_key}
    try:
        response = requests.get(url + ":"+ port + PROCESS_SEARCH_URL+QUERY_PARAMETER+query, headers=headers, verify=False, timeout=5)
        if (response.status_code == UNAUTHORIZED_CODE):
            print ("Authentication Token is invalid or expired!")
            sys.exit()
        elif(response.status_code == SUCCESS_CODE):
            return (response.json()['total_results'])
        else:
            print ("An unexpected error has occurred. Please check Carbon Black url and port.")
            sys.exit()
    except requests.exceptions.Timeout:
        print("Connection could not be established")
        sys.exit()

def generateSubQueriesforBigQuery(query,limit):
    subqueries = []
    index = 0
    tempQuery = ""
    queries = query.split(OR_OPERATOR)
    print (len(queries))
    for counter in range(0,len(queries)):
        if index == limit or counter == len(queries) - 1:
            subqueries.append(tempQuery[:-3])
            tempQuery = ""
            index = 1
        else:
            tempQuery += queries[counter] + OR_OPERATOR
            index += 1
    return list(filter(None, subqueries))

def main():
    requests.packages.urllib3.disable_warnings()
    print (PROGRAM_NAME)
    analyzer.init()
    api_key,url,port = readConfigFile()
    articles = getArticlesWithIndicators(analyzer)
    if (len(articles) != 0):
        timeForFilename = time.strftime("%Y%m%d-%H%M%S")
        output = open(OUTPUT_FILENAME+timeForFilename+EXTENTION, mode='w')
        output_writer = csv.writer(output, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        output_writer.writerow(['Report_Title','Report_Summary','Report_Link','Query','Total_Result_Count'])
        for article in articles:
            for indicator in article.indicators:
                reportTitle = (article.title)
                reportSummary = (article.summary)
                reportLink = (article.link)
                query = (prepareCarbonBlackSearchQuery(indicator))
                if query is not None:
                    if query.count("OR") < LIMIT:
                        result = searchQueryOnCarbonBlack(api_key,url,port,query)
                        output_writer.writerow([reportTitle,reportSummary,reportLink,query,result])
                    else:
                        subqueries = generateSubQueriesforBigQuery(query,LIMIT)
                        for subquery in subqueries:
                            result = searchQueryOnCarbonBlack(api_key,url,port,subquery)
                            output_writer.writerow([reportTitle,reportSummary,reportLink,subquery,result])
    else:
        print ("No feeds containing indicators were found in the specified time period.")
            
if __name__ == "__main__":
    main()