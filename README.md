![alt tag](https://github.com/1N3/BlackWidow/blob/master/blackwidowlogo.png)

## ABOUT:
BlackWidow is a python based web application spider to gather subdomains, URL's, dynamic parameters, email addresses and phone numbers from a target website. This project also includes Inject-X fuzzer to scan dynamic URL's for common OWASP vulnerabilities.

## DEMO VIDEO:
[![BlackWidow Demo](https://i.ytimg.com/vi/mch8ht47taY/hqdefault.jpg)](https://www.youtube.com/watch?v=mch8ht47taY)

## FEATURES:
- [x] Automatically collect all URL's from a target website
- [x] Automatically collect all dynamic URL's and parameters from a target website
- [x] Automatically collect all subdomains from a target website
- [x] Automatically collect all phone numbers from a target website
- [x] Automatically collect all email addresses from a target website
- [x] Automatically collect all form URL's from a target website
- [X] Automatically scan/fuzz for common OWASP TOP vulnerabilities
- [x] Automatically saves all data into sorted text files

## LINUX INSTALL:
```
cp blackwidow /usr/bin/blackwidow 
cp injectx.py /usr/bin/injectx.py
pip install -r requirements.txt
```

## USAGE:
```
blackwidow -u https://target.com - crawl target.com with 3 levels of depth.
blackwidow -d target.com -l 5 - crawl the domain: target.com with 5 levels of depth.
blackwidow -d target.com -l 5 -c 'test=test' - crawl the domain: target.com with 5 levels of depth using the cookie 'test=test'
blackwidow -d target.com -l 5 -s y - crawl the domain: target.com with 5 levels of depth and fuzz all unique parameters for OWASP vulnerabilities.
injectx.py https://test.com/uers.php?user=1&admin=true - Fuzz all GET parameters for common OWASP vulnerabilities.
```

## SAMPLE REPORT:
![alt tag](https://github.com/1N3/BlackWidow/blob/master/blackwidow-report1.png)

## DOCKER:
```bash
git clone https://github.com/1N3/BlackWidow.git
cd BlackWidow
docker build -t blackwidow .
docker run -it blackwidow # Defaults to --help

```

## LICENSE:
This software is released under the GNU General Public License v3.0. See LICENSE.md for details.

## DONATIONS:
Donations are welcome. This will help facilitate improved features, frequent updates and better overall support.
- [+] BTC 1Fav36btfmdrYpCAR65XjKHhxuJJwFyKum
- [+] ETH 0x20bB09273702eaBDFbEE9809473Fd04b969a794d
- [+] LTC LQ6mPewec3xeLBYMdRP4yzeta6b9urqs2f
- [+] XMR 4JUdGzvrMFDWrUUwY3toJATSeNwjn54LkCnKBPRzDuhzi5vSepHfUckJNxRL2gjkNrSqtCoRUrEDAgRwsQvVCjZbS3EN24xprAQ1Z5Sy5s
- [+] ZCASH t1fsizsk2cqqJAjRoUmXJSyoVa9utYucXt7

## SOCIAL MEDIA:
- [Twitter](https://www.twitter.com/crowdshield "Twitter")
- [YouTube](https://www.yahoo.com/crowdshield "YouTube")
- [Blog](https://crowdshield.com/blog.php "Blog")
- [BugCrowd](https://bugcrowd.com/1N3 "BugCrowd")
- [HackerOne](https://hackerone.com/1N3 "HackerOne")
