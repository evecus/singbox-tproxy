package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/sagernet/sing-box/box"
)

type Config struct {
	Inbounds []struct {
		Type   string `json:"type"`
		Listen int    `json:"listen_port"`
	} `json:"inbounds"`
}

func main() {
	lan := flag.String("lan", "", "内网网段 (例: 192.168.31.0/24)")
	ipv6Mode := flag.String("ipv6", "", "IPv6 模式: 'enable' 或 'disable'")
	configPath := flag.String("c", "", "config.json 路径")
	flag.Parse()

	if *lan == "" || *ipv6Mode == "" || *configPath == "" {
		fmt.Println("用法: sudo ./sing-box-tproxy --lan <网段> --ipv6 <enable|disable> -c <配置文件>")
		os.Exit(1)
	}

	// 1. 环境准备
	ensureNftables()
	port := getTProxyPort(*configPath)
	
	[cite_start]// 2. 配置网络规则 [cite: 1, 4, 13]
	cleanup() 
	if err := setup(*lan, *ipv6Mode, port); err != nil {
		log.Fatalf("网络规则设置失败: %v", err)
	}

	// 3. 启动核心
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	content, err := os.ReadFile(*configPath)
	if err != nil {
		log.Fatalf("读取配置失败: %v", err)
	}

	// 使用最新版本的 Options 初始化
	instance, err := box.New(box.Options{
		Context:       ctx,
		ConfigContent: string(content),
	})
	if err != nil {
		log.Fatalf("核心初始化失败: %v", err)
	}

	if err := instance.Start(); err != nil {
		log.Fatalf("核心启动失败: %v", err)
	}

	fmt.Println("[+] 代理引擎与 TProxy 规则已成功运行")

	// 4. 信号处理
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	fmt.Println("\n[-] 正在清理并关闭...")
	instance.Close()
	[cite_start]cleanup() // [cite: 8, 11]
}

// --- 辅助函数保持一致 ---

func ensureNftables() {
	if _, err := exec.LookPath("nft"); err != nil {
		managers := map[string]string{"apt-get": "install -y nftables", "yum": "install -y nftables", "pacman": "-S --noconfirm nftables"}
		for m, args := range managers {
			if _, e := exec.LookPath(m); e == nil {
				if m == "apt-get" { exec.Command(m, "update").Run() }
				exec.Command(m, strings.Split(args, " ")...).Run()
				break
			}
		}
	}
	[cite_start]exec.Command("systemctl", "enable", "--now", "nftables").Run() // [cite: 1]
}

func getTProxyPort(path string) string {
	file, _ := os.ReadFile(path)
	var cfg Config
	json.Unmarshal(file, &cfg)
	for _, in := range cfg.Inbounds {
		if in.Type == "tproxy" { return fmt.Sprintf("%d", in.Listen) }
	}
	log.Fatal("未找到 tproxy 入站端口")
	return ""
}

func setup(lan, ipv6, port string) error {
	nftCmd := fmt.Sprintf(`
	table inet singbox_tproxy {
		chain prerouting {
			type filter hook prerouting priority mangle; policy accept;
			ip daddr { 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } return
			ip daddr %s tcp dport != 53 return
			meta l4proto { tcp, udp } tproxy to :%s meta mark set 1
		}
		chain output {
			type route hook output priority mangle; policy accept;
			meta mark 1 return
			meta l4proto { tcp, udp } meta mark set 1
		}
	[cite_start]}`, lan, port) // [cite: 13, 16]

	os.WriteFile("/tmp/sb.nft", []byte(nftCmd), 0644)
	if out, err := exec.Command("nft", "-f", "/tmp/sb.nft").CombinedOutput(); err != nil {
		return fmt.Errorf("%s", string(out))
	}

	[cite_start]exec.Command("ip", "rule", "add", "fwmark", "1", "lookup", "100").Run() // [cite: 4]
	exec.Command("ip", "route", "add", "local", "default", "dev", "lo", "table", "100").Run()
	if ipv6 == "enable" {
		[cite_start]exec.Command("ip", "-6", "rule", "add", "fwmark", "1", "lookup", "100").Run() // [cite: 6]
		exec.Command("ip", "-6", "route", "add", "local", "default", "dev", "lo", "table", "100").Run()
	}
	return nil
}

func cleanup() {
	[cite_start]exec.Command("nft", "delete", "table", "inet", "singbox_tproxy").Run() // [cite: 11]
	[cite_start]exec.Command("ip", "rule", "del", "fwmark", "1", "lookup", "100").Run() // [cite: 9]
	exec.Command("ip", "route", "del", "local", "default", "dev", "lo", "table", "100").Run()
	exec.Command("ip", "-6", "rule", "del", "fwmark", "1", "lookup", "100").Run()
	exec.Command("ip", "-6", "route", "del", "local", "default", "dev", "lo", "table", "100").Run()
}
