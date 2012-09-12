# A lightweight bypass censorship system for HTTP

## Introduction

It works by inspecting the packets between servers and clients. If some
sensitive words are seen, it will log the corresponding criterias.

## License

It is released under GPL v3.

## Copyright

Changli Gao <xiaosuo@gmail.com>

## Requirements

* [libpcap](http://www.tcpdump.org)
* [zlib](http://www.zlib.net)

## Install

Compile the code with

    $ make

Install the program with

    $ sudo make install

or

    # make install

## Configurations

### Rules

The default rule file is */etc/snoopy/rules.conf*, and you can set it to another
file with option *-R* too.

A rule occupies one line, and *IP Sections* and *Port Sections* are separated
with *:*. You can specify *IP*, *IP Range* and *IP Subnet* for *IP Sections*,
and you can specify *Port* and *Port Range* for *Port Sections*.

Ex.

    192.168.0.0/24:80
    10.0.0.1-10.0.0.10:80-8080
    10.10.10.10:8080

### Keywords

The default keyword file is */etc/snoopy/keywords.conf*, and you can set it to
another file with option *-k* too.

A keyword occupies one line, must be encoded in UTF-8, and must _NOT_ contains
any space.

Ex.

    test
    你好

## Run

See the help message with

    snoopy -h

## Log

The default log file is */var/log/snoopy.log*, and you can set it to another
file with option *-l* too.

A log occupies one line, and contains *Timestamp*(derived from
[RFC3339](http://tools.ietf.org/html/rfc3339)), *Client IP*, *Server IP*,
*URL* and *Keyword*, which are separated by space.

Ex.

    2012-08-15T15:22:52.682786Z 172.168.0.252 172.168.0.2 http://172.168.0.2/index.html?11a11221=111122a222 welcome
