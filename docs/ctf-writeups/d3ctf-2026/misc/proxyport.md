---
title: "proxyport"
ctf: "D3CTF 2026"
date: 2026-08-05
category: misc
difficulty: easy
points: 500
flag_format: "d3ctf{...}"
author: "Antigravity Team"
---

# proxyport

## Summary

**proxyport** is a network protocol analysis challenge focused on detecting `frp` (Fast Reverse Proxy) TCP forwarding ports by probing incomplete implementations of the TCP state machine during connection teardown.

---

## Technical Details & Vulnerability Analysis

1. **Standard TCP Teardown Behavior**:
   In standard TCP, when Client A sends a `FIN` packet (`CloseWrite()`), it only closes the stream from A to B (half-closed state). Client A can still receive data sent from B to A until Server B closes its side.

2. **FRP TCP Forwarding Flaw**:
   `frp`'s application-layer TCP forwarding logic does not fully implement half-closed TCP states. When a client sends a `FIN`, `frp` treats the connection as closed in **both** directions. As a result, any response data sent by the server after the client's `FIN` is dropped.

3. **Detection Mechanism**:
   We connect to the target port, send an HTTP request, immediately issue a `CloseWrite()` (FIN), and attempt to read from the socket.
   - Standard HTTP reverse proxy / `gost`: Returns the HTTP response data successfully.
   - `frp` reverse proxy: Returns 0 bytes without timing out because the connection was forcibly closed in both directions upon receiving the `FIN`.

---

## Detection Script (Go)

```go
package main

import (
    "fmt"
    "io"
    "log"
    "net"
    "os"
    "sync"
    "sync/atomic"
    "time"
    "crypto/tls"
)

func identifyService(addr string) (string, error) {
    var (
        wg          sync.WaitGroup
        confirmFrp  atomic.Bool
    )

    for i := 0; i < 5; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            conn, err := tls.DialWithDialer(&net.Dialer{
                Timeout: 3 * time.Second,
            }, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
            if err != nil {
                log.Printf("[probe] dial error: %v", err)
                return
            }
            defer conn.Close()

            conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
            if _, err := fmt.Fprintf(conn, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", addr); err != nil {
                log.Printf("[probe] write error: %v", err)
                return
            }

            // Close write direction (send FIN)
            conn.CloseWrite()
            conn.SetReadDeadline(time.Now().Add(800 * time.Millisecond))

            response, err := io.ReadAll(conn)
            if err != nil && !os.IsTimeout(err) {
                log.Printf("[probe] read error: %v", err)
                return
            }

            // If 0 bytes read and no timeout occurred, FRP connection teardown detected
            if len(response) == 0 && !os.IsTimeout(err) {
                confirmFrp.Store(true)
            }
        }()
    }

    wg.Wait()
    if confirmFrp.Load() {
        return "frp", nil
    }
    return "gost", nil
}

func main() {
    result, err := identifyService("target.d3ctf.io:443")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Detected Reverse Proxy: %s\n", result)
}
```

---

## Flag

```
d3ctf{frp_tcp_fin_state_machine_detection_success}
```
