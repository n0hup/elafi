# Elixir Ads Filter (ελάφι)

https://en.wiktionary.org/wiki/ελάφι#Greek


## Apps

- dnsauth: authoritative nameserver, for lan
- dnscache: recursive resolver
- shades: blacklist/whitelist
- webui: settings & monitoring

### DNS

#### Message Format

All communications inside of the domain protocol are carried in a single
format called a message.  The top level format of message is divided
into 5 sections (some of which are empty in certain cases) shown below:

    +---------------------+
    |        Header       |
    +---------------------+
    |       Question      | the question for the name server
    +---------------------+
    |        Answer       | RRs answering the question
    +---------------------+
    |      Authority      | RRs pointing toward an authority
    +---------------------+
    |      Additional     | RRs holding additional information
    +---------------------+



##### Header

https://www.zytrax.com/books/dns/ch15/#header

##### Question

https://www.zytrax.com/books/dns/ch15/#question

##### Answer

https://www.zytrax.com/books/dns/ch15/#answer

##### Authority

https://www.zytrax.com/books/dns/ch15/#authority

##### Additional

https://www.zytrax.com/books/dns/ch15/#additional

## Resources

- https://www.ietf.org/rfc/rfc1035.txt
- https://www.zytrax.com/books/dns/ch15/
- https://www2.cs.duke.edu/courses/fall16/compsci356/DNS/DNS-primer.pdf
