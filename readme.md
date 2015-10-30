Ever wanted to do DNSSEC validation in PHP?

This dnssec validator is written in 100% PHP5. It contains an object-oriented DNS module that can retrieve any record from a nameserver.

No other modules or downloads needed

The validator has been tested extensively on .NL and .EU domain names, but not on other ones.

Please feel free to test, use, add or modify.

To use this suite: 
- Clone this repository
- php test.php <domainname>

At this time it will only test .nl, .eu and .com domains because the nameservers are known for these extensions. Nameservers can be added for other extensions.
See DNS/dnsProtocol.php function registrynameservers()