# tplink-wan

A small CLI for managing a TP-Link **XX230v** (AX1800 Dual Band Wi-Fi 6 GPON
Router) from the command line. Lets you list every WAN profile, enable or
disable individual WANs, reconnect a specific PPPoE link, or reboot the
router — using the same encrypted CGI calls the web UI makes.

Tested on `XX230v` v1.0 firmware (ISP-customized). Likely works on related
TP-Link MR / EX firmware variants that talk to `/cgi_gdpr?9` with the
JSON envelope described below.

## Why

The web UI lets you toggle individual WAN connections, but there's no
official CLI for this router. A full reboot is heavy when all you want
is to reconnect one PPPoE link — for example, when your ISP rotates
your IP and you want a quick refresh without dropping IPTV or VoIP.

## Install

### With `go install`

If you have Go 1.21+ installed:

```sh
go install github.com/ikholmatov/tplink-wan@latest
```

This drops a `tplink-wan` binary into `$(go env GOBIN)` (or `$(go env GOPATH)/bin`
if `GOBIN` is unset). Make sure that directory is on your `PATH`. To get the
shorter `wan` name from the examples below, symlink it:

```sh
ln -s "$(go env GOPATH)/bin/tplink-wan" "$(go env GOPATH)/bin/wan"
```

### Download a prebuilt binary

Grab the release for your platform from the [Releases page](../../releases),
`chmod +x`, and put it somewhere on your `PATH`.

### Build from source

Requires Go 1.21+ (no other dependencies — uses only the standard library).

```sh
git clone https://github.com/ikholmatov/tplink-wan.git
cd tplink-wan
go build -o wan ./...
```

Cross-compile for another host:

```sh
GOOS=linux  GOARCH=amd64 go build -o wan-linux-amd64 ./...
GOOS=linux  GOARCH=arm64 go build -o wan-linux-arm64 ./...
GOOS=linux  GOARCH=arm   go build -o wan-linux-arm   ./...  # Raspberry Pi
GOOS=darwin GOARCH=arm64 go build -o wan-darwin-arm64 ./...
```

## Configure

Each setting can be provided three ways. Resolution order:

1. **CLI flag** — `-host`, `-user`, `-password`
2. **Environment variable** — `TPLINK_HOST`, `TPLINK_USER`, `TPLINK_PASSWORD`
3. **`.env` file** beside the binary (or in the current directory)

| Setting   | Flag         | Env var           | Default              |
| --------- | ------------ | ----------------- | -------------------- |
| Host      | `-host`      | `TPLINK_HOST`     | `http://192.168.1.1` |
| User      | `-user`      | `TPLINK_USER`     | `user`               |
| Password  | `-password`  | `TPLINK_PASSWORD` | *(required)*         |

The host accepts a bare IP (`192.168.1.1`) or a full URL
(`http://192.168.1.1`). The XX230v firmware logs in as `user`, not `admin`.

Example `.env`:

```ini
TPLINK_PASSWORD=your-router-password
TPLINK_HOST=http://192.168.1.1
TPLINK_USER=user
```

```sh
chmod 600 .env   # keep the password readable only to your user
```

> **Avoid `-password` on the command line in production**: it shows up in
> `ps`, in shell history, and in any process-listing tool other users on
> the box can run. Prefer the env var or `.env` file for routine use, and
> reserve `-password` for quick one-off testing.

## Usage

```
wan [flags] <command> [name]

  status                    summary + WAN list
  wan-list                  list every WAN (name, stack, type, enable, status, IP)
  wan-disable [name]        set enable=0 on a WAN (default: pppoe_gpon_3_3)
  wan-enable  [name]        set enable=1
  wan-reconnect [name]      disable then enable back-to-back
  reboot                    reboot the whole router

Flags:
  -host string      router URL or IP (default: env or http://192.168.1.1)
  -user string      login user       (default: env or user)
  -password string  login password   (default: env, required)
```

The `[name]` argument accepts either the WAN's display name (e.g.
`pppoe_gpon_3_3`) or its stack (`5,0,0,0,0,0`). Auto-detect with `wan-list`.

### Example session

```sh
$ wan wan-list
NAME                   STACK          TYPE     ENABLE  STATUS        IP
usb_ppp3g              1,0,0,0,0,0    PPP3G    1       Disconnected  0.0.0.0
usb_dhcp4g             2,0,0,0,0,0    DHCP4G   1       Disconnected  0.0.0.0
ipoe_0_0_d             3,0,0,0,0,0    DHCP     1       Disconnected  0.0.0.0
ipoe_gpon_0_1_d        4,0,0,0,0,0    DHCP     1       Disconnected  0.0.0.0
pppoe_gpon_3_3         5,0,0,0,0,0    PPPoE    1       Connected     100.76.116.81
ipoe_gpon_0_4_d        6,0,0,0,0,0    DHCP     1       Disconnected  0.0.0.0

$ wan wan-reconnect
WAN "pppoe_gpon_3_3" reconnect sent
```

### One-off against a different router

```sh
wan -host 10.0.0.1 -user admin -password "$ROUTER_PW" wan-list
```

### Scheduling with cron

To kick the main PPPoE every night at 4 AM:

```cron
0 4 * * *  cd /opt/tplink-wan && ./wan wan-reconnect >> /var/log/wan.log 2>&1
```

## How it works

The XX230v web UI talks to a single encrypted endpoint:

```
POST /cgi_gdpr?9
Headers: TokenID: <token>, Cookie: JSESSIONID=...
Body:    sign=<RSA-hex>\r\ndata=<AES-base64>\r\n
```

For each WAN action it sends a JSON envelope inside the encrypted `data=` blob:

```json
{
  "data":      { "stack": "5,0,0,0,0,0", "pstack": "0,0,0,0,0,0", "enable": "0" },
  "operation": "so",
  "oid":       "DEV2_ADT_WAN"
}
```

Where `operation` is one of `go` (get) · `gl` (get list) · `gs` (get sub) ·
`so` (set) · `ao` (add) · `do` (delete) · `op` (operation) · `cgi`.

### Authentication flow

1. `POST /cgi/getGDPRParm` returns the router's RSA public key (`nn`, `ee`)
   and a sequence number (`seq`).
2. The client generates a fresh AES-128 key and IV (16 ASCII digits each),
   computes `h = md5(username + password)`, and builds the login JSON
   `{ "data":{ "UserName":"<b64>", "Passwd":"<b64>", ... }, "operation":"cgi",
   "oid":"/cgi/login" }`.
3. The JSON is AES-CBC encrypted (PKCS#7-padded, base64-encoded).
4. The signature is **raw RSA (no padding)** of the string
   `key=<aes-key>&iv=<aes-iv>&h=<md5>&s=<seq+data_len>`, split into 64-byte
   chunks (each zero-padded), each chunk RSA-encrypted, then hex-concatenated.
5. POST `sign=<hex>\r\ndata=<base64>\r\n` to `/cgi_gdpr?9`. The router
   returns `$.ret=0;` and sets a `JSESSIONID` cookie.
6. GET `/` once; the index page contains
   `<script>var token="…";</script>`. That token is sent as the `TokenID`
   header on every subsequent CGI call.
7. Per request afterwards, the signature drops the AES key/IV: just
   `h=<md5>&s=<seq+data_len>` (1 RSA block = 128 hex chars).

The `tplinkrouterc6u` Python library implements the same handshake; this
project is a from-scratch Go port using only the standard library.

### Gotchas worth knowing

If you build something similar for an MR/EX-family TP-Link, watch out for:

- The signing key uses field names **`key=…&iv=…`**, not the abbreviated
  `k=…&i=…` that some older firmware uses.
- The RSA on this firmware is **raw / no padding** (zero-pad the plaintext
  to the block size), not PKCS#1 v1.5. Block plaintext = full key byte
  length (64 bytes for 512-bit RSA).
- WAN entries live at `DEV2_ADT_WAN` (the WAN-config layer), while
  underlying PPP interfaces are at `DEV2_PPP_INTF`. The display name
  `pppoe_gpon_3_3` is at `DEV2_ADT_WAN` stack `5,0,0,0,0,0`, but the
  same connection's `ppp1` is at `DEV2_PPP_INTF` stack `3,0,0,0,0,0`.
  Toggle at the WAN layer.
- The router's HTTP server hangs after `Set-Cookie` on `/cgi/login` (it
  promises a 9-byte body that never arrives). Either avoid that endpoint
  entirely (this project uses `/cgi_gdpr?9` for login) or use a short
  read timeout and swallow the EOF.

## Security notes

- The `.env` file holds your router password in plaintext on disk —
  treat the file like an SSH key. Don't commit it.
- All traffic between this tool and the router goes over **HTTP**, not
  HTTPS. Anyone on the same LAN can sniff the AES-encrypted body, but
  the AES key is RSA-encrypted with the router's public key, so the
  plaintext payload stays confidential to that router. The login
  password is also RSA-encrypted inside the request.
- If your password has been exposed (shared in a chat, screenshot,
  etc.), rotate it in the router UI — it doubles as the AES key
  material derivation input.

## Status

Personal project, used daily for refreshing one PPPoE link. Issues and
patches welcome, especially for other XX230v-family firmware variants.

## License

[MIT](./LICENSE)
