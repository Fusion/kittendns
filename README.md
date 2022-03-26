# What is this?

A toy DNS for hobbyists and worried people.

Several goals:

- Rule engine to rewrite/deny queries (implemented)
- Dirt simple to configure (toml syntax)
- No fat. Fast.

# Configuration

Take a look at the content of the `config.toml.template` file. Copy it to `config.toml` and run.

# Tell me more about the DNS repository

In the `github.com/miekg/dns` repository, there was a pull request allowing code using that library to retrieve additional information about the requesting socket. This includes source IP, which can be convenient in a split horizon environment. It lives in this directory (slightly adapted)

# Todo

Cache
- if flattening is enabled, we should cache the flattened version

Flattening
- What about multi answers?