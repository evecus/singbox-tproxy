package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
)

type Config struct {
	Inbounds []struct {
		Type   string `json:"type"`
		Listen int    `json:"listen_port"`
	} `json:"inbounds"`
}

func main() {
	lan := flag.String("lan", "", "内网网段 (如: 192.168.31.0/24)")
	ipv6Mode := flag.String("ipv6", "", "IPv6 模式: 'enable' 或 'disable'")
	configPath := flag.String("c", "", "config.json 路径")
	flag.Parse()

	if *lan == "" || *ipv6Mode == "" || *configPath == "" {
		fmt.Println("用法: sing-box-tproxy --lan <网段> --ipv6 <enable|disable> -c <配置文件>")
		os.Exit(1)
	}

	ensureNftables()

	port := getTProxyPort(*configPath)
	fmt.Printf("[-] 检测到 TProxy 端口: %s\n", port)

	fmt.Println("[-] 正在配置网络规则...")
	cleanup() 
	if err := setup(*lan, *ipv6Mode, port); err != nil {
		log.Fatalf("致命错误: 规则应用失败: %v", err)
	}

	cmd := exec.Command("sing-box", "run", "-c", *configPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := cmd.Start(); err != nil {
			log.Fatalf("启动 sing-box 失败: %v", err)
		}
		cmd.Wait()
		sigChan <- syscall.SIGTERM
	}()

	<-sigChan
	fmt.Println("\n[-] 正在清理环境并退出...")
	cleanup()
}

func ensureNftables() {
	_, err := exec.LookPath("nft")
	if err != nil {
		fmt.Println("[!] 未检测到 nftables，正在尝试安装...")
		managers := []string{"apt-get", "yum", "pacman"}
		installed := false
		for _, m := range managers {
			if _, e := exec.LookPath(m); e == nil {
				if m == "apt-get" { exec.Command(m, "update").Run() }
				args := strings.Split("install -y nftables", " ")
				if m == "pacman" { args = strings.Split("-S --noconfirm nftables", " ") }
				if exec.Command(m, args...).Run() == nil {
					installed = true
					break
				}
			}
		}
		if !installed { log.Fatal("无法自动安装 nftables，请手动安装") }
	}
	exec.Command("systemctl", "enable", "--now", "nftables").Run()
}

func getTProxyPort(path string) string {
	file, err := os.ReadFile(path)
	if err != nil { log.Fatalf("读取配置失败: %v", err) }
	var cfg Config
	if err := json.Unmarshal(file, &cfg); err != nil { log.Fatalf("JSON 解析失败: %v", err) }
	for _, in := range cfg.Inbounds {
		if in.Type == "tproxy" { return fmt.Sprintf("%d", in.Listen) }
	}
	log.Fatal("未在配置中找到 tproxy 入站")
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

	tmpFile := "/tmp/sb_tproxy.nft"
	os.WriteFile(tmpFile, []byte(nftCmd), 0644)
	if out, err := exec.Command("nft", "-f", tmpFile).CombinedOutput(); err != nil {
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
