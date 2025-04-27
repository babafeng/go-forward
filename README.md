# go-forward

A simple traffic forwarding tool

## build

```bash
go build -ldflags="-s -w"
```

## Intranet Reverse Proxy

Server

```bash
go-forward -L :7000
```

Client

```bash
go-forward -L 2080//127.0.0.1:1080 -F your.server.com:7000
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

Listen on port 2080 and forward traffic to 10.0.0.1:1080

```bash
go-forward -L 2080//10.0.0.1:1080
```
