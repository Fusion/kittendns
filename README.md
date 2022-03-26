# What is this?

Kittens!

# Tell me more about the DNS repository

In the `github.com/miekg/dns` repository, there was a pull request allowing code using that library to retrieve additional information about the requesting socket. This includes source IP, which can be convenient in a split horizon environment. It lives in this directory (slightly adapted)

todo

Cache
- hostname as index
- add an expiration timestamp that is now + TTL
- if flattening is enabled, we should cache the flattened version

Flattening
- what about multi answers?