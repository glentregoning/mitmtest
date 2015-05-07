# MITMTest - Verify you're App's not vulnerable to Man in the Middle Attacks #

## Installation ##

Clone this repository to your local system:
i.e. 
```
cd ~/
git clone git@github.com:glentregoning/mitmtest.git 
cd ~/mitmtest
```

### Installing Dependencies ###
```
sudo easy_install pip
sudo -H pip install mitmproxy --upgrade
```

## Usage ##
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
