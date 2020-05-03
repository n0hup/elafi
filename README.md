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


Header + Question must be included for both request and reponse. Answer can be compressed with pointers to the question section.

Example query and response without pointers:


                         +-----------------------------------------+
           Header        |          OPCODE=IQUERY, ID=123          |
                         +-----------------------------------------+
          Question       |  QTYPE=A, QCLASS=IN, QNAME=WEB.MIT.EDU  |
                         +-----------------------------------------+
           Answer        |                 <empty>                 |
                         +-----------------------------------------+
          Authority      |                 <empty>                 |
                         +-----------------------------------------+
         Additional      |                 <empty>                 |
                         +-----------------------------------------+


                         +-----------------------------------------+
           Header        |         OPCODE=RESPONSE, ID=123         |
                         +-----------------------------------------+
          Question       |  QTYPE=A, QCLASS=IN, QNAME=WEB.MIT.EDU  |
                         +-----------------------------------------+
           Answer        |       WEB.MIT.EDU A IN 104.96.143.80    |
                         +-----------------------------------------+
          Authority      |                 <empty>                 |
                         +-----------------------------------------+
         Additional      |                 <empty>                 |
                         +-----------------------------------------+                         

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
