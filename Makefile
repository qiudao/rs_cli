.PHONY: all build cli gui clean install-vuln run-vuln stop-vuln help

# 默认目标
all: build

# 编译所有
build: cli gui

# 编译 CLI 版本
cli:
	@echo "[*] 编译 CLI 版本..."
	go build -o nextjs-cli cli.go
	@echo "[+] 完成: nextjs-cli"

# 编译 GUI 版本
gui:
	@echo "[*] 编译 GUI 版本..."
	go build -o nextjs-gui main.go
	@echo "[+] 完成: nextjs-gui"

# 清理编译产物
clean:
	@echo "[*] 清理..."
	rm -f nextjs-cli nextjs-gui
	rm -rf vuln-test/node_modules vuln-test/.next
	@echo "[+] 清理完成"

# 安装漏洞测试环境
install-vuln:
	@echo "[*] 安装漏洞测试环境..."
	@if [ ! -d "vuln-test" ]; then \
		echo "[!] vuln-test 目录不存在"; \
		exit 1; \
	fi
	cd vuln-test && npm install
	@echo "[+] 安装完成"
	@echo "[*] 运行 'make run-vuln' 启动测试服务器"

# 启动漏洞测试服务器
run-vuln:
	@echo "[*] 启动漏洞测试服务器..."
	@if [ ! -d "vuln-test/node_modules" ]; then \
		echo "[!] 请先运行 'make install-vuln'"; \
		exit 1; \
	fi
	cd vuln-test && npm run dev

# 后台启动漏洞测试服务器
run-vuln-bg:
	@echo "[*] 后台启动漏洞测试服务器..."
	@if [ ! -d "vuln-test/node_modules" ]; then \
		echo "[!] 请先运行 'make install-vuln'"; \
		exit 1; \
	fi
	cd vuln-test && npm run dev > /dev/null 2>&1 &
	@sleep 3
	@echo "[+] 服务器已在后台运行: http://localhost:3000"

# 停止测试服务器
stop-vuln:
	@echo "[*] 停止测试服务器..."
	@pkill -f "next dev" 2>/dev/null || true
	@echo "[+] 已停止"

# 测试 CLI
test:
	@echo "[*] 测试 CLI..."
	./nextjs-cli check -t http://localhost:3000
	@echo ""
	./nextjs-cli check -t http://localhost:3000 --active

# 帮助
help:
	@echo "Next.js RCE Exploit Tool - Makefile"
	@echo ""
	@echo "用法: make [target]"
	@echo ""
	@echo "编译:"
	@echo "  make build       - 编译 CLI 和 GUI"
	@echo "  make cli         - 仅编译 CLI"
	@echo "  make gui         - 仅编译 GUI"
	@echo "  make clean       - 清理编译产物"
	@echo ""
	@echo "测试环境:"
	@echo "  make install-vuln - 安装漏洞测试环境依赖"
	@echo "  make run-vuln     - 启动测试服务器 (前台)"
	@echo "  make run-vuln-bg  - 启动测试服务器 (后台)"
	@echo "  make stop-vuln    - 停止测试服务器"
	@echo ""
	@echo "测试:"
	@echo "  make test        - 测试 CLI (需先启动测试服务器)"
