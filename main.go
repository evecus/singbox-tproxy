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
	// 默认值全部设为空，强制要求用户输入
	lan := flag.String("lan", "", "IPv4 内网网段 (必填, 例: 10.0.0.0/24)")
	ipv6Mode := flag.String("ipv6", "", "IPv6 模式 (必填, 选项: enable | disable)")
	configPath := flag.String("c", "", "配置文件路径 (必填)")
	flag.Parse()

	// 1. 检查命令行硬性参数
	if *lan == "" || *configPath == "" || *ipv6Mode == "" {
		fmt.Println("\n[!] 启动失败: 缺少硬性命令行参数！")
		fmt.Println("用法: sudo ./sing-box-tproxy --lan [网段] --ipv6 [enable|disable] -c [配置文件]")
		os.Exit(1)
	}

	// 2. 校验 IPv6 参数合法性
	if *ipv6Mode != "enable" && *ipv6Mode != "disable" {
		log.Fatalf("[!] 启动失败: --ipv6 参数必须是 enable 或 disable")
	}

	// 3. 检查并提取 TProxy 端口 (如果找不到则直接在函数内 Exit)
	port := getTProxyPortOrDie(*configPath)

	// --- 只有通过以上所有检查，才会执行到这里 ---

	// 4. 释放内核
	tempDir := "/tmp/.sb_runtime"
	os.MkdirAll(tempDir, 0755)
	targetCore := filepath.Join(tempDir, "sing-box")
	if err := os.WriteFile(targetCore, embeddedSingBox, 0755); err != nil {
		log.Fatalf("[!] 释放内核失败: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// 5. 环境清理与规则应用
	cleanup()
	if err := setupRules(*lan, *ipv6Mode, port); err != nil {
		log.Fatalf("[!] 设置网络规则失败: %v", err)
	}

	// 6. 运行核心
	cmd := exec.Command(targetCore, "run", "-c", *configPath)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := cmd.Start(); err != nil {
			log.Printf("[!] 核心启动失败: %v", err)
			return
		}
		cmd.Wait()
		sigChan <- syscall.SIGTERM
	}()

	fmt.Printf("[+] 所有检查通过，程序已安全启动！\n")
	fmt.Printf("[+] 模式: IPv4=%s | IPv6=%s | TProxyPort=%s\n", *lan, *ipv6Mode, port)
	
	<-sigChan
	cleanup()
}

// 核心逻辑：找不到 tproxy 端口直接终止程序
func getTProxyPortOrDie(path string) string {
	file, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("[!] 启动失败: 无法读取配置文件 %s: %v", path, err)
	}

	var cfg Config
	if err := json.Unmarshal(file, &cfg); err != nil {
		log.Fatalf("[!] 启动失败: 配置文件 JSON 格式解析错误: %v", err)
	}

	for _, in := range cfg.Inbounds {
		if in.Type == "tproxy" {
			if in.Listen != 0 {
				return fmt.Sprintf("%d", in.Listen)
			}
		}
	}

	// 如果循环结束还没找到有效端口，直接拒绝运行
	fmt.Printf("\n[!] 严重错误: 配置文件 %s 中未检测到 \"type\": \"tproxy\" 配置！\n", path)
	fmt.Println("[!] 为避免造成流量黑洞或 SSH 永久失联，程序拒绝启动。")
	fmt.Println("[!] 请在 config.json 的 inbounds 中添加 tproxy 配置后再试。")
	os.Exit(1)
	return ""
}

func setupRules(lan, ipv6Mode, port string) error {
	v6Bypass := ""
	if ipv6Mode == "enable" {
		v6Bypass = "ip6 daddr { ::1/128, fc00::/7, fe80::/10 } return"
	}

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
			%s 
			meta l4proto { tcp, udp } tproxy to :%s meta mark set 1
		}
		chain output {
			type route hook output priority mangle; policy accept;
			ip daddr @RESERVED_IP return
			ip daddr %s return
			%s
			meta mark 1 return
			meta l4proto { tcp, udp } meta mark set 1
		}
	}`, lan, v6Bypass, port, lan, v6Bypass)

	os.WriteFile("/tmp/sb.nft", []byte(nftRules), 0644)
	if err := exec.Command("nft", "-f", "/tmp/sb.nft").Run(); err != nil {
		return fmt.Errorf("nft 加载失败 (请确认是否安装了 nftables)")
	}

	// 应用路由
	exec.Command("ip", "rule", "add", "fwmark", "1", "lookup", "100").Run()
	exec.Command("ip", "route", "add", "local", "default", "dev", "lo", "table", "100").Run()
	if ipv6Mode == "enable" {
		exec.Command("ip", "-6", "rule", "add", "fwmark", "1", "lookup", "100").Run()
		exec.Command("ip", "-6", "route", "add", "local", "default", "dev", "lo", "table", "100").Run()
	}
	return nil
}

func cleanup() {
	fmt.Println("[-] 正在清理网络规则...")
	exec.Command("nft", "delete", "table", "inet", "singbox_tproxy").Run()
	// 清理 IPv4 和 IPv6 策略路由
	for _, args := range [][]string{
		{"rule", "del", "fwmark", "1", "lookup", "100"},
		{"route", "del", "local", "default", "dev", "lo", "table", "100"},
	} {
		exec.Command("ip", args...).Run()
		exec.Command("ip", append([]string{"-6"}, args...)...).Run()
	}
}
