package main

import (
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
)

//go:embed sing-box-core
var embeddedSingBox []byte

type Config struct {
	Inbounds []struct {
		Type   string `json:"type"`
		Listen int    `json:"listen_port"`
	} `json:"inbounds"`
}

func main() {
	lan := flag.String("lan", "", "内网网段 (例: 10.0.0.0/24)")
	ipv6Mode := flag.String("ipv6", "disable", "IPv6 模式: enable 或 disable")
	configPath := flag.String("c", "", "配置文件路径")
	flag.Parse()

	if *lan == "" || *configPath == "" {
		fmt.Println("用法: sudo ./sing-box-tproxy --lan 10.0.0.0/24 --ipv6 disable -c config.json")
		os.Exit(1)
	}

	// 1. 释放内嵌内核
	tempDir := "/tmp/.sb_runtime"
	os.MkdirAll(tempDir, 0755)
	targetCore := filepath.Join(tempDir, "sing-box")
	if err := os.WriteFile(targetCore, embeddedSingBox, 0755); err != nil {
		log.Fatalf("释放内核失败: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// 2. 环境初始化
	cleanup()
	port := getTProxyPort(*configPath)
	if err := setupRules(*lan, *ipv6Mode, port); err != nil {
		log.Fatalf("设置规则失败: %v", err)
	}

	// 3. 运行核心
	cmd := exec.Command(targetCore, "run", "-c", *configPath)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := cmd.Start(); err != nil {
			log.Printf("内核启动失败: %v", err)
			return
		}
		cmd.Wait()
		sigChan <- syscall.SIGTERM
	}()

	fmt.Printf("[+] 集成版 Sing-box 已启动\n[+] 转发端口: %s\n[+] 排除网段: %s\n", port, *lan)
	<-sigChan
	cleanup()
}

func getTProxyPort(path string) string {
	file, err := os.ReadFile(path)
	if err != nil {
		return "7893"
	}
	var cfg Config
	json.Unmarshal(file, &cfg)
	for _, in := range cfg.Inbounds {
		if in.Type == "tproxy" {
			return fmt.Sprintf("%d", in.Listen)
		}
	}
	return "7893"
}

func setupRules(lan, ipv6, port string) error {
	// 关键：在 Output 链也加入排除逻辑，彻底解决 SSH/全端口断连问题
	nftRules := fmt.Sprintf(`
	table inet singbox_tproxy {
		set RESERVED_IP { 
			type ipv4_addr; flags interval; 
			elements = { 100.64.0.0/10, 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } 
		}
		chain prerouting {
			type filter hook prerouting priority mangle; policy accept;
			ip daddr @RESERVED_IP return
			ip daddr %s return
			meta l4proto { tcp, udp } tproxy to :%s meta mark set 1
		}
		chain output {
			type route hook output priority mangle; policy accept;
			ip daddr @RESERVED_IP return
			ip daddr %s return
			meta mark 1 return
			meta l4proto { tcp, udp } meta mark set 1
		}
	}`, lan, port, lan)

	os.WriteFile("/tmp/sb.nft", []byte(nftRules), 0644)
	if err := exec.Command("nft", "-f", "/tmp/sb.nft").Run(); err != nil {
		return fmt.Errorf("nft 加载失败")
	}

	exec.Command("ip", "rule", "add", "fwmark", "1", "lookup", "100").Run()
	exec.Command("ip", "route", "add", "local", "default", "dev", "lo", "table", "100").Run()

	if ipv6 == "enable" {
		exec.Command("ip", "-6", "rule", "add", "fwmark", "1", "lookup", "100").Run()
		exec.Command("ip", "-6", "route", "add", "local", "default", "dev", "lo", "table", "100").Run()
	}
	return nil
}

func cleanup() {
	fmt.Println("[-] 正在清理网络规则...")
	exec.Command("nft", "delete", "table", "inet", "singbox_tproxy").Run()
	exec.Command("ip", "rule", "del", "fwmark", "1", "lookup", "100").Run()
	exec.Command("ip", "route", "del", "local", "default", "dev", "lo", "table", "100").Run()
	exec.Command("ip", "-6", "rule", "del", "fwmark", "1", "lookup", "100").Run()
	exec.Command("ip", "-6", "route", "del", "local", "default", "dev", "lo", "table", "100").Run()
}
