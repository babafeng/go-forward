# go-forward

A simple traffic forwarding tool

## build

```bash
go build -ldflags="-s -w"
```

## Intranet Reverse Tunnel

Server

```bash
go-forward -L :7000
```

Client

```bash
go-forward -L 1000//127.0.0.1:1080 -F your.server.com:7000

```

## Local Proxy

Supports HTTP and SOCKS5 proxies

```bash
go-forward -L http://0.0.0.0:1080
go-forward -L http://username:password@0.0.0.0:1080

go-forward -L socks5://0.0.0.0:1080
go-forward -L socks5://username:password@0.0.0.0:1080
```

## Local TCP traffic forward

Listen on port 1000 and forward traffic to 10.0.0.1:1080

```bash
go-forward -L 1000//10.0.0.1:1080
```

Listen on port 1000-1005 and forward traffic to 10.0.0.1:1000-1005

```bash
go-forward -L 1000-1005//10.0.0.1:1000-1005
```


## Use tips

While starting the proxy locally, forward the proxy port to the remote port

```bash
go-forward -L http://127.0.0.1:1080 -L 2020//127.0.0.1:1080 -F your.server.com:7000
```

Start HTTP and SOCKS5 proxy locally at the same time

```bash
go-forward -L http://0.0.0.0:1080 -L socks5://0.0.0.0:1080

go-forward -L http://0.0.0.0:1080 -L socks5://0.0.0.0:1081 -L 1000//127.0.0.1:1080 -L 1001//127.0.0.1:1081 -F your.server.com:7000
```

The same server supports multiple intranet clients

```bash
# Intranet Host 1:
go-forward -L 1000//127.0.0.1:1080 -F your.server.com:7000

# Intranet Host 2:
go-forward -L 1001//127.0.0.1:1080 -F your.server.com:7000

# Intranet Host 3:
go-forward -L 1002//127.0.0.1:1080 -F your.server.com:7000

...
```
