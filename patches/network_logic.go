package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// AutoSetupSideGateway 执行旁路由所需的网络初始化
func AutoSetupSideGateway() {
	// 仅在以 root 权限运行且不是 help/version 命令时执行
	if os.Geteuid() != 0 || (len(os.Args) > 1 && (os.Args[1] == "version" || os.Args[1] == "help")) {
		return
	}

	fmt.Println("[+] 检测到 Root 权限，正在自动配置 TPROXY 旁路由环境...")

	// 1. 开启内核转发与修复 rp_filter
	exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()
	exec.Command("sysctl", "-w", "net.ipv4.conf.all.rp_filter=0").Run()
	exec.Command("sysctl", "-w", "net.ipv4.conf.default.rp_filter=0").Run()
	exec.Command("sysctl", "-w", "net.ipv4.conf.all.send_redirects=0").Run()

	// 2. 注入 nftables 规则 (适配你的 7893 和 1053 端口)
	// 包含：DNS劫持、绕过局域网、TPROXY、NAT伪装
	nftScript := `
table inet sb_auto {
    set bypass_list {
        type ipv4_addr; flags interval
        elements = { 10.0.0.0/8, 127.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 }
    }
    chain prerouting {
        type filter hook prerouting priority mangle; policy accept;
        udp dport 53 tproxy to :1053 accept
        tcp dport 53 tproxy to :1053 accept
        ip daddr @bypass_list return
        meta mark 0xff return
        meta l4proto { tcp, udp } meta mark set 1 tproxy to :7893
    }
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        ip saddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } masquerade
    }
}`
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(nftScript)
	if err := cmd.Run(); err != nil {
		fmt.Printf("[-] nftables 配置失败: %v\n", err)
	}

	// 3. 配置策略路由
	exec.Command("ip", "rule", "add", "fwmark", "1", "table", "100").Run()
	exec.Command("ip", "route", "add", "local", "default", "dev", "lo", "table", "100").Run()

	fmt.Println("[+] 旁路由网络规则已就绪 (TPROXY:7893, DNS:1053)")
}