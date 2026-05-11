// wan — CLI to control a TP-Link XX230v (AX1800 GPON) router.
// Talks to /cgi_gdpr?9 with the same JSON envelope the web UI uses.
package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Client struct {
	host     string
	username string
	password string

	hash   string   // md5(username + password) hex
	nn     *big.Int // router RSA modulus
	ee     int      // router RSA public exponent
	seq    int64    // running sequence number from router
	aesKey []byte   // 16-byte ASCII key (used as raw AES key)
	aesIV  []byte   // 16-byte ASCII IV
	token  string   // TokenID header value

	http *http.Client
}

func NewClient(host, username, password string) (*Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	h := md5.Sum([]byte(username + password))
	return &Client{
		host:     strings.TrimRight(host, "/"),
		username: username,
		password: password,
		hash:     hex.EncodeToString(h[:]),
		http: &http.Client{
			Jar:     jar,
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				DisableCompression: true, // router rejects requests with Accept-Encoding: gzip
				DisableKeepAlives:  false,
			},
		},
	}, nil
}

// fetchRSAParams reads /cgi/getGDPRParm: ee, nn, seq.
func (c *Client) fetchRSAParams() error {
	req, _ := http.NewRequest("POST", c.host+"/cgi/getGDPRParm", nil)
	req.Header.Set("Referer", c.host+"/")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36")
	req.Header.Set("Accept", "*/*")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	text := string(body)

	get := func(name string) string {
		re := regexp.MustCompile(`var ` + name + `="([^"]+)"`)
		m := re.FindStringSubmatch(text)
		if len(m) < 2 {
			return ""
		}
		return m[1]
	}
	nnHex, eeHex, seqStr := get("nn"), get("ee"), get("seq")
	if nnHex == "" || eeHex == "" || seqStr == "" {
		return fmt.Errorf("could not parse RSA params from: %s", text)
	}
	c.nn = new(big.Int)
	c.nn.SetString(nnHex, 16)
	ee, err := strconv.ParseInt(eeHex, 16, 32)
	if err != nil {
		return err
	}
	c.ee = int(ee)
	c.seq, err = strconv.ParseInt(seqStr, 10, 64)
	return err
}

// genAES generates the AES key + IV the way the web UI does: first 16 chars
// of a timestamp + random-digits string. The router uses these ASCII bytes
// directly as the AES key, not the bytes they would decode to.
func (c *Client) genAES() {
	pad := func() []byte {
		ts := strconv.FormatInt(time.Now().UnixMilli(), 10)
		buf := make([]byte, 4)
		_, _ = rand.Read(buf)
		r := binary.BigEndian.Uint32(buf)
		s := ts + strconv.FormatUint(uint64(r), 10) + strings.Repeat("0", 16)
		return []byte(s[:16])
	}
	c.aesKey = pad()
	c.aesIV = pad()
}

// rsaEncryptChunked replicates the MR firmware's signing: raw RSA (no padding),
// split plaintext into <rsa-byte-length> chunks, zero-pad the tail of each
// chunk, concatenate hex outputs.
func (c *Client) rsaEncryptChunked(plain string) string {
	rsaByteLen := (c.nn.BitLen() + 7) / 8
	step := rsaByteLen
	e := big.NewInt(int64(c.ee))
	hexLen := rsaByteLen * 2
	var out strings.Builder
	for i := 0; i < len(plain); i += step {
		end := min(i+step, len(plain))
		buf := make([]byte, step)          // zero-padded by default
		copy(buf, plain[i:end])
		m := new(big.Int).SetBytes(buf)
		ct := new(big.Int).Exp(m, e, c.nn)
		fmt.Fprintf(&out, "%0*x", hexLen, ct)
	}
	return out.String()
}

func pkcs7Pad(b []byte, blockSize int) []byte {
	pad := blockSize - len(b)%blockSize
	return append(b, bytes.Repeat([]byte{byte(pad)}, pad)...)
}

func pkcs7Unpad(b []byte) []byte {
	if len(b) == 0 {
		return b
	}
	pad := int(b[len(b)-1])
	if pad < 1 || pad > aes.BlockSize || pad > len(b) {
		return b
	}
	return b[:len(b)-pad]
}

func (c *Client) aesEncrypt(plain string) string {
	block, _ := aes.NewCipher(c.aesKey)
	mode := cipher.NewCBCEncrypter(block, c.aesIV)
	padded := pkcs7Pad([]byte(plain), aes.BlockSize)
	ct := make([]byte, len(padded))
	mode.CryptBlocks(ct, padded)
	return base64.StdEncoding.EncodeToString(ct)
}

func (c *Client) aesDecrypt(b64 string) (string, error) {
	ct, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return "", fmt.Errorf("decode base64: %w", err)
	}
	if len(ct)%aes.BlockSize != 0 {
		return "", fmt.Errorf("ciphertext not block-aligned: %d", len(ct))
	}
	block, _ := aes.NewCipher(c.aesKey)
	mode := cipher.NewCBCDecrypter(block, c.aesIV)
	pt := make([]byte, len(ct))
	mode.CryptBlocks(pt, ct)
	return string(pkcs7Unpad(pt)), nil
}

// post sends the standard sign+data envelope to /cgi_gdpr?9.
func (c *Client) post(plain string, isLogin bool) (string, error) {
	encrypted := c.aesEncrypt(plain)
	seqWithLen := c.seq + int64(len(encrypted))
	var sigPlain string
	if isLogin {
		sigPlain = fmt.Sprintf("key=%s&iv=%s&h=%s&s=%d",
			c.aesKey, c.aesIV, c.hash, seqWithLen)
	} else {
		sigPlain = fmt.Sprintf("h=%s&s=%d", c.hash, seqWithLen)
	}
	sign := c.rsaEncryptChunked(sigPlain)

	body := "sign=" + sign + "\r\ndata=" + encrypted + "\r\n"
	req, _ := http.NewRequest("POST", c.host+"/cgi_gdpr?9", strings.NewReader(body))
	req.Header.Set("Accept", "text/plain, */*; q=0.01")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Referer", c.host+"/")
	req.Header.Set("Origin", c.host)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36")
	if c.token != "" {
		req.Header.Set("TokenID", c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("http %d: %s", resp.StatusCode, rb)
	}
	if len(rb) == 0 {
		return "", nil
	}
	return c.aesDecrypt(string(rb))
}

func (c *Client) Authorize() error {
	if err := c.fetchRSAParams(); err != nil {
		return fmt.Errorf("rsa params: %w", err)
	}
	c.genAES()

	loginPayload := fmt.Sprintf(
		`{"data":{"UserName":"%s","Passwd":"%s","Action":"1","stack":"0,0,0,0,0,0","pstack":"0,0,0,0,0,0"},"operation":"cgi","oid":"/cgi/login"}`,
		base64.StdEncoding.EncodeToString([]byte(c.username)),
		base64.StdEncoding.EncodeToString([]byte(c.password)),
	)
	resp, err := c.post(loginPayload, true)
	if err != nil {
		return fmt.Errorf("login post: %w", err)
	}
	if !strings.Contains(resp, "$.ret=0") {
		return fmt.Errorf("login rejected: %s", resp)
	}

	// Pull the TokenID injected as `var token="…"` in the post-login index page.
	req, _ := http.NewRequest("GET", c.host+"/", nil)
	req.Header.Set("Referer", c.host+"/")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36")
	req.Header.Set("Accept", "text/html,*/*;q=0.8")
	r2, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("fetch token page: %w", err)
	}
	defer r2.Body.Close()
	page, _ := io.ReadAll(r2.Body)
	tm := regexp.MustCompile(`var token="([^"]+)"`).FindSubmatch(page)
	if len(tm) < 2 {
		return fmt.Errorf("token not found in / (login likely lacks privilege)")
	}
	c.token = string(tm[1])
	return nil
}

// Call sends a JSON op via /cgi_gdpr?9 and decodes the response.
func (c *Client) Call(operation, oid, stack string, extra map[string]string) (map[string]any, error) {
	if stack == "" {
		stack = "0,0,0,0,0,0"
	}
	data := map[string]any{"stack": stack, "pstack": "0,0,0,0,0,0"}
	for k, v := range extra {
		data[k] = v
	}
	payload := map[string]any{
		"data":      data,
		"operation": operation,
		"oid":       oid,
	}
	b, _ := json.Marshal(payload)
	resp, err := c.post(string(b)+"\r\n", false)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(resp), &out); err != nil {
		return nil, fmt.Errorf("decode %q: %w", resp, err)
	}
	return out, nil
}

// findWAN looks up a WAN entry by display name OR stack.
func (c *Client) findWAN(nameOrStack string) (map[string]any, error) {
	r, err := c.Call("gl", "DEV2_ADT_WAN", "", nil)
	if err != nil {
		return nil, err
	}
	if ok, _ := r["success"].(bool); !ok {
		return nil, fmt.Errorf("list wans: %v", r)
	}
	list, _ := r["data"].([]any)
	for _, item := range list {
		w, _ := item.(map[string]any)
		if w["name"] == nameOrStack || w["stack"] == nameOrStack {
			return w, nil
		}
	}
	return nil, fmt.Errorf("WAN %q not found (try `wan-list`)", nameOrStack)
}

// loadEnv reads simple KEY=VALUE lines from a .env-style file.
func loadEnv(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if os.Getenv(k) == "" {
			os.Setenv(k, v)
		}
	}
}

const usageTmpl = `Usage: %s [flags] <command> [name]

Commands:
  status                    summary + WAN list
  wan-list                  list every WAN (name, stack, type, status, IP)
  wan-disable [name]        set enable=0 on a WAN (default: pppoe_gpon_3_3)
  wan-enable  [name]        set enable=1
  wan-reconnect [name]      disable then enable, back-to-back
  reboot                    reboot the router

Flags (override env / .env):
  -host string      router URL or IP   (env TPLINK_HOST, default http://192.168.1.1)
  -user string      login user         (env TPLINK_USER, default user)
  -password string  login password     (env TPLINK_PASSWORD, required)

NOTE: passing -password on the command line exposes it to other processes
(via ps) and shell history. Prefer TPLINK_PASSWORD in env or a chmod-600
.env file beside the binary.
`

func usage() string {
	return fmt.Sprintf(usageTmpl, filepath.Base(os.Args[0]))
}

// pick returns the first non-empty string.
func pick(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func main() {
	exe, _ := os.Executable()
	loadEnv(filepath.Join(filepath.Dir(exe), ".env"))
	loadEnv(".env")

	flagHost := flag.String("host", "", "router URL or IP (env TPLINK_HOST, default http://192.168.1.1)")
	flagUser := flag.String("user", "", "login user (env TPLINK_USER, default user)")
	flagPass := flag.String("password", "", "login password (env TPLINK_PASSWORD, required)")
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage()) }
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
		os.Exit(1)
	}
	cmd := args[0]
	arg := "pppoe_gpon_3_3"
	if len(args) > 1 {
		arg = args[1]
	}

	host := pick(*flagHost, os.Getenv("TPLINK_HOST"), "http://192.168.1.1")
	username := pick(*flagUser, os.Getenv("TPLINK_USER"), "user")
	password := pick(*flagPass, os.Getenv("TPLINK_PASSWORD"))
	if password == "" {
		die("password required (use -password, TPLINK_PASSWORD env, or a .env file)")
	}
	// Accept bare hosts: "192.168.1.1" → "http://192.168.1.1"
	if u, err := url.Parse(host); err != nil || u.Scheme == "" {
		host = "http://" + host
	}

	c, err := NewClient(host, username, password)
	if err != nil {
		die("client: %v", err)
	}
	if err := c.Authorize(); err != nil {
		die("authorize: %v", err)
	}

	switch cmd {
	case "status":
		printStatus(c)
	case "wan-list":
		printWANList(c)
	case "wan-disable":
		wanSet(c, arg, "0")
	case "wan-enable":
		wanSet(c, arg, "1")
	case "wan-reconnect":
		wanReconnect(c, arg)
	case "reboot":
		reboot(c)
	default:
		fmt.Fprint(os.Stderr, usage())
		os.Exit(1)
	}
}

func printStatus(c *Client) {
	// DEV2_DEV_INFO would give model/firmware; for now just show WAN list.
	printWANList(c)
}

func printWANList(c *Client) {
	r, err := c.Call("gl", "DEV2_ADT_WAN", "", nil)
	if err != nil {
		die("wan-list: %v", err)
	}
	if ok, _ := r["success"].(bool); !ok {
		die("wan-list: %v", r)
	}
	fmt.Printf("%-22s %-14s %-8s %-7s %-13s %s\n",
		"NAME", "STACK", "TYPE", "ENABLE", "STATUS", "IP")
	list, _ := r["data"].([]any)
	for _, item := range list {
		w, _ := item.(map[string]any)
		fmt.Printf("%-22s %-14s %-8s %-7s %-13s %s\n",
			str(w["name"]), str(w["stack"]), str(w["connType"]),
			str(w["enable"]), str(w["connStatusV4"]), str(w["connIPv4Address"]))
	}
}

func wanSet(c *Client, nameOrStack, enable string) {
	w, err := c.findWAN(nameOrStack)
	if err != nil {
		die("%v", err)
	}
	stack := str(w["stack"])
	r, err := c.Call("so", "DEV2_ADT_WAN", stack, map[string]string{"enable": enable})
	if err != nil {
		die("set: %v", err)
	}
	if ok, _ := r["success"].(bool); !ok {
		die("set rejected: %v", r)
	}
	fmt.Printf("WAN %q (stack %s) -> enable=%s\n", str(w["name"]), stack, enable)
}

func wanReconnect(c *Client, nameOrStack string) {
	w, err := c.findWAN(nameOrStack)
	if err != nil {
		die("%v", err)
	}
	stack := str(w["stack"])
	for _, v := range []string{"0", "1"} {
		r, err := c.Call("so", "DEV2_ADT_WAN", stack, map[string]string{"enable": v})
		if err != nil {
			die("set enable=%s: %v", v, err)
		}
		if ok, _ := r["success"].(bool); !ok {
			die("set enable=%s rejected: %v", v, r)
		}
	}
	fmt.Printf("WAN %q reconnect sent\n", str(w["name"]))
}

func reboot(c *Client) {
	r, err := c.Call("op", "ACT_REBOOT", "", nil)
	if err != nil {
		die("reboot: %v", err)
	}
	if ok, _ := r["success"].(bool); !ok {
		die("reboot rejected: %v", r)
	}
	fmt.Println("reboot command sent.")
}

func str(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}
