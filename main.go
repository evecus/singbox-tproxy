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

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/option"
)

type SBConfig struct {
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

	ensureNftables()
	port := getTProxyPort(*configPath)
	
	cleanup() 
	if err := setup(*lan, *ipv6Mode, port); err != nil {
		log.Fatalf("网络规则设置失败: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	content, err := os.ReadFile(*configPath)
	if err != nil {
		log.Fatalf("读取配置失败: %v", err)
	}

	var options option.Options
	if err := json.Unmarshal(content, &options); err != nil {
		log.Fatalf("解析配置失败: %v", err)
	}

	instance, err := singbox.New(singbox.Options{
		Context: ctx,
		Options: options,
	})
	if err != nil {
		log.Fatalf("核心初始化失败: %v", err)
	}

	if err := instance.Start(); err != nil {
		log.Fatalf("核心启动失败: %v", err)
	}

	fmt.Println("[+] Sing-box 嵌入式核心与 TProxy 规则已成功启动")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	fmt.Println("\n[-] 正在清理并退出...")
	instance.Close()
	cleanup()
}

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
	exec.Command("systemctl", "enable", "--now", "nftables").Run()
}

func getTProxyPort(path string) string {
	file, _ := os.ReadFile(path)
	var cfg SBConfig
	json.Unmarshal(file, &cfg)
	for _, in := range cfg.Inbounds {
		if in.Type == "tproxy" { return fmt.Sprintf("%d", in.Listen) }
	}
	log.Fatal("未在配置中找到 tproxy 入站端口")
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
	}`, lan, port)

	os.WriteFile("/tmp/sb.nft", []byte(nftCmd), 0644)
	if out, err := exec.Command("nft", "-f", "/tmp/sb.nft").CombinedOutput(); err != nil {
		return fmt.Errorf("%s", string(out))
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
	exec.Command("nft", "delete", "table", "inet", "singbox_tproxy").Run()
	exec.Command("ip", "rule", "del", "fwmark", "1", "lookup", "100").Run()
	exec.Command("ip", "route", "del", "local", "default", "dev", "lo", "table", "100").Run()
	exec.Command("ip", "-6", "rule", "del", "fwmark", "1", "lookup", "100").Run()
	exec.Command("ip", "-6", "route", "del", "local", "default", "dev", "lo", "table", "100").Run()
}
