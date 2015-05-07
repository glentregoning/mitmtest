# MITMTest - Verify you're App's not vulnerable to Man in the Middle Attacks #

## Installation ##
_Instructions tested on OSX_

Clone this repository to your local system:
i.e. 
```
cd ~/
git clone git@github.com:glentregoning/mitmtest.git 
cd ~/mitmtest

```

Installing Dependencies:
```
sudo easy_install pip
sudo -H pip install mitmproxy --upgrade
```



## Usage

1. Run mitmtest.sh
 1. ```./mitmtest.sh --test insecure``` tests applications against accepting insecure / self signed certificates
 2. ```./mitmtest.sh --test domain``` domain validation, testing applications against accepting certificates domains other than the one being connected to. 
2. Configure your device (e.g. iPhone / Android or iOS Simulator) to use your computer as it's proxy server on port 8080
3. [Required test 'domain' validation] 
 1. Open a webbrowser on your device, and visit http://mitm.it. 
 2. Select the option matching your device to install a MITM root certificate. (see here for more information: http://mitmproxy.org/doc/certinstall/webapp.html). 
 3. NOTE: If you don't install this certificate the  ```--test domain``` mode won't work (and will PASS every connection whether its secure or not).
4. Run your app on your device, and watch the mitmtest.sh output the results of tests for hosts your app is test.

## mitmtest.sh Command Arguments

```
usage: mitmtest.sh [-h] [--test {insecure,domain,none}] [--suppress-pass]
                   [example.com, an.example.com [example.com, an.example.com ...]]

Test for Man In The Middle Vulnerabilities, including acceptance of self-
signed/insecure certificates ("--test insecure"), and verification the
certificate domain name matches the host connecting to ("--test domain").

positional arguments:
  example.com, an.example.com
                        domains under test

optional arguments:
  -h, --help            show this help message and exit
  --test {insecure,domain,none}
                        MITM test to run: 'insecure' (default): test with
                        self-signed / insecure certificate, 'domain'= test the
                        application verifies the domain of the certificate
                        matches the host it's connecting to.
  --suppress-pass       don't print hosts which pass the MITM test
```

## Author ##

Glen Tregoning, [@glent](http://twitter.com/glent)

## License

MITMTest is available under the MIT license. See the [LICENSE](LICENSE) file for full details. 
