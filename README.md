# Elixir Ads Filter (ελάφι)

https://en.wiktionary.org/wiki/ελάφι#Greek

## Apps

- dnsauth: authoritative nameserver, for lan
- dnscache: recursive resolver
- shades: blacklist/whitelist
- webui: settings & monitoring

## Motivation

Fighting ads supposed to be more accessible. I really like Pihole but it has more dependencies that I am comfortable with (dnsmasq, lighttpd, php, Bootstrap 3.x, etc.).

## Dependecies

I try to not to use any dependecies. Esqlite is a NIF based library. It might be worth to start up as a separate application.

```Elixir
  defp deps do
    [
      {:esqlite, "~> 0.4.1"},
      {:elli, "~> 3.2"}
    ]
  end
```

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

##### Pcap

- query

      Domain Name System (query)
          Transaction ID: 0x1483
          Flags: 0x0100 Standard query
              0... .... .... .... = Response: Message is a query
              .000 0... .... .... = Opcode: Standard query (0)
              .... ..0. .... .... = Truncated: Message is not truncated
              .... ...1 .... .... = Recursion desired: Do query recursively
              .... .... .0.. .... = Z: reserved (0)
              .... .... ...0 .... = Non-authenticated data: Unacceptable
          Questions: 1
          Answer RRs: 0
          Authority RRs: 0
          Additional RRs: 0
          Queries
              rpi4.lan: type A, class IN
                  Name: rpi4.lan
                  [Name Length: 8]
                  [Label Count: 2]
                  Type: A (Host Address) (1)
                  Class: IN (0x0001)

bytes:

    0000   b8 27 eb a8 3d a3 dc a6 32 75 b6 86 08 00 45 00   .'..=...2u....E.
    0010   00 36 13 a2 00 00 40 11 e2 ed c0 a8 01 6e c0 a8   .6....@......n..
    0020   01 69 ae 33 00 35 00 22 34 53 14 83 01 00 00 01   .i.3.5."4S......
    0030   00 00 00 00 00 00 04 72 70 69 34 03 6c 61 6e 00   .......rpi4.lan.
    0040   00 01 00 01                                       ....


- response

      Domain Name System (response)
          Transaction ID: 0x1483
          Flags: 0x8180 Standard query response, No error
              1... .... .... .... = Response: Message is a response
              .000 0... .... .... = Opcode: Standard query (0)
              .... .0.. .... .... = Authoritative: Server is not an authority for domain
              .... ..0. .... .... = Truncated: Message is not truncated
              .... ...1 .... .... = Recursion desired: Do query recursively
              .... .... 1... .... = Recursion available: Server can do recursive queries
              .... .... .0.. .... = Z: reserved (0)
              .... .... ..0. .... = Answer authenticated: Answer/authority portion was not authenticated by the server
              .... .... ...0 .... = Non-authenticated data: Unacceptable
              .... .... .... 0000 = Reply code: No error (0)
          Questions: 1
          Answer RRs: 1
          Authority RRs: 0
          Additional RRs: 0
          Queries
              rpi4.lan: type A, class IN
                  Name: rpi4.lan
                  [Name Length: 8]
                  [Label Count: 2]
                  Type: A (Host Address) (1)
                  Class: IN (0x0001)
          Answers
              rpi4.lan: type A, class IN, addr 192.168.1.110
                  Name: rpi4.lan
                  Type: A (Host Address) (1)
                  Class: IN (0x0001)
                  Time to live: 1489 (24 minutes, 49 seconds)
                  Data length: 4
                  Address: 192.168.1.110

bytes:

      0000   dc a6 32 75 b6 86 b8 27 eb a8 3d a3 08 00 45 00   ..2u...'..=...E.
      0010   00 46 97 0e 40 00 40 11 1f 71 c0 a8 01 69 c0 a8   .F..@.@..q...i..
      0020   01 6e 00 35 ae 33 00 32 2b b7 14 83 81 80 00 01   .n.5.3.2+.......
      0030   00 01 00 00 00 00 04 72 70 69 34 03 6c 61 6e 00   .......rpi4.lan.
      0040   00 01 00 01 c0 0c 00 01 00 01 00 00 05 d1 00 04   ................
      0050   c0 a8 01 6e                                       ...n




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
