package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

type Config struct {
	Inbounds []struct {
		Type   string `json:"type"`
		Listen int    `json:"listen_port"`
	} `json:"inbounds"`
}

func main() {
	// 1. 定义强制性参数
	lan := flag.String("lan", "", "内网网段 (如: 192.168.31.0/24)")
	ipv6Mode := flag.String("ipv6", "", "IPv6 模式: 'enable' 或 'disable'")
	configPath := flag.String("c", "", "config.json 路径")
	flag.Parse()

	if *lan == "" || *ipv6Mode == "" || *configPath == "" {
		fmt.Println("错误: 缺少必要参数")
		fmt.Println("用法: sing-box-tproxy --lan <网段> --ipv6 <enable|disable> -c <配置文件>")
		os.Exit(1)
	}

	// 2. 环境检查与自动安装
	ensureNftables()

	// 3. 解析端口
	port := getTProxyPort(*configPath)
	fmt.Printf("[-] 检测到 TProxy 端口: %s\n", port)

	// 4. 应用规则
	fmt.Println("[-] 正在配置网络规则...")
	cleanup() // 先清理旧规则 [cite: 8-11]
	if err := setup(*lan, *ipv6Mode, port); err != nil {
		log.Fatalf("致命错误: 规则应用失败 (请检查内核是否支持 TProxy): %v", err)
	}

	// 5. 启动 sing-box
	cmd := exec.Command("sing-box", "run", "-c", *configPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// 信号监听
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
	cleanup() [cite: 8-12]
}

func ensureNftables() {
	_, err := exec.LookPath("nft")
	if err != nil {
		fmt.Println("[!] 未检测到 nftables，正在尝试安装...")
		// 自动安装 (以 Debian/Ubuntu 为例)
		installCmd := exec.Command("apt-get", "update")
		installCmd.Run()
		if err := exec.Command("apt-get", "install", "-y", "nftables").Run(); err != nil {
			log.Fatalf("无法安装 nftables，请手动安装: %v", err)
		}
	}
	// 启动并开机自启
	exec.Command("systemctl", "enable", "--now", "nftables").Run()
	fmt.Println("[+] nftables 服务已就绪")
}

func getTProxyPort(path string) string {
	file, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("无法读取配置文件: %v", err)
	}
	var cfg Config
	if err := json.Unmarshal(file, &cfg); err != nil {
		log.Fatalf("JSON 格式错误: %v", err)
	}
	for _, in := range cfg.Inbounds {
		if in.Type == "tproxy" {
			return fmt.Sprintf("%d", in.Listen)
		}
	}
	log.Fatal("错误: 在 config.json 中未找到 tproxy 类型的入站配置")
	return ""
}

func setup(lan, ipv6, port string) error {
	// 生成 nftables 脚本 [cite: 13-17]
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
	
	// 执行并检查错误
	if out, err := exec.Command("nft", "-f", tmpFile).CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, string(out))
	}

	// 路由表配置 [cite: 4-7]
	exec.Command("ip", "rule", "add", "fwmark", "1", "lookup", "100").Run()
	exec.Command("ip", "route", "add", "local", "default", "dev", "lo", "table", "100").Run()

	if ipv6 == "enable" {
		exec.Command("ip", "-6", "rule", "add", "fwmark", "1", "lookup", "100").Run()
		exec.Command("ip", "-6", "route", "add", "local", "default", "dev", "lo", "table", "100").Run()
	}
	return nil
}

func cleanup() {
	// 彻底清理规则 [cite: 8-12]
	exec.Command("nft", "delete", "table", "inet", "singbox_tproxy").Run()
	exec.Command("ip", "rule", "del", "fwmark", "1", "lookup", "100").Run()
	exec.Command("ip", "route", "del", "local", "default", "dev", "lo", "table", "100").Run()
	exec.Command("ip", "-6", "rule", "del", "fwmark", "1", "lookup", "100").Run()
	exec.Command("ip", "-6", "route", "del", "local", "default", "dev", "lo", "table", "100").Run()
}
