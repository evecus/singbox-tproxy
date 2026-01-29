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
	"strings"
	"syscall"
	"time"
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
	// 强制硬性参数检测
	lan := flag.String("lan", "", "IPv4 内网网段 (必填, 例: 10.0.0.0/24)")
	ipv6Mode := flag.String("ipv6", "", "IPv6 模式 (必填: enable | disable)")
	configPath := flag.String("c", "", "配置文件路径 (必填)")
	flag.Parse()

	if *lan == "" || *configPath == "" || *ipv6Mode == "" {
		fmt.Printf("\n[!] 启动失败: 缺少硬性参数\n用法: sudo ./sing-box-tproxy --lan 10.0.0.0/24 --ipv6 disable -c config.json\n")
		os.Exit(1)
	}

	// 1. 进程检测：运行前必须检查并清理现有的 sing-box
	checkAndKillExistingProcess()

	// 2. 配置检测：提取 TProxy 端口，失败则不进行任何网络改动
	port := getTProxyPortOrDie(*configPath)

	// 3. 准备内核文件
	tempDir := "/tmp/.sb_runtime"
	os.MkdirAll(tempDir, 0755)
	targetCore := filepath.Join(tempDir, "sing-box")
	if err := os.WriteFile(targetCore, embeddedSingBox, 0755); err != nil {
		log.Fatalf("[!] 释放内核失败: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// 4. 加载规则：仅加载一次，失败则回滚并退出
	fmt.Println("[*] 正在初始化网络规则 (包含详细 IPv4/IPv6 保留地址)...")
	if err := setupRules(*lan, *ipv6Mode, port); err != nil {
		fmt.Printf("[!] 网络规则加载失败: %v\n", err)
		cleanup() 
		os.Exit(1)
	}

	// 5. 启动内核：设置父子进程同步死掉的属性
	cmd := exec.Command(targetCore, "run", "-c", *configPath)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	if err := cmd.Start(); err != nil {
		fmt.Printf("[!] Sing-box 启动失败: %v，正在回滚规则...\n", err)
		cleanup()
		os.Exit(1)
	}

	fmt.Printf("[+] 启动成功! 模式: IPv4=%s, IPv6=%s, TProxyPort=%s\n", *lan, *ipv6Mode, port)

	// 6. 退出监听与清理
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-sigChan:
		fmt.Println("\n[*] 接收到停止信号，正在清理环境...")
	case err := <-done:
		fmt.Printf("\n[!] 内核进程意外停止: %v，正在清理环境...\n", err)
	}

	cleanup()
	fmt.Println("[+] 所有规则已清空，进程已杀灭，安全退出。")
}

func checkAndKillExistingProcess() {
	out, _ := exec.Command("pgrep", "-f", "sing-box").Output()
	if len(strings.Fields(string(out))) > 0 {
		fmt.Println("[!] 发现现有 sing-box 进程，正在强制清理...")
		exec.Command("killall", "-9", "sing-box").Run()
		time.Sleep(500 * time.Millisecond)
	}
}

func getTProxyPortOrDie(path string) string {
	file, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("[!] 无法读取配置文件: %v", err)
	}
	var cfg Config
	if err := json.Unmarshal(file, &cfg); err != nil {
		log.Fatalf("[!] 配置文件 JSON 解析失败: %v", err)
	}
	for _, in := range cfg.Inbounds {
		if in.Type == "tproxy" && in.Listen != 0 {
			return fmt.Sprintf("%d", in.Listen)
		}
	}
	fmt.Println("[!] 错误: config.json 中未发现有效的 tproxy 入站配置，拒绝运行。")
	os.Exit(1)
	return ""
}

func setupRules(lan, ipv6Mode, port string) error {
	// 部署前确保清理干净旧表和旧路由，防止重复添加
	cleanupNetwork()

	// IPv6 保留地址 (根据你的 .nft 文件定义)
	v6Bypass := ""
	if ipv6Mode == "enable" {
		v6Bypass = `
		ip6 daddr { ::/128, ::1/128, ::ffff:0:0/96, 64:ff9b::/96, 100::/64, 2001::/32, 2001:20::/28, 2001:db8::/32, 2002::/16, fc00::/7, fe80::/10, ff00::/8 } return
		`
	}

	// 整合你提供的 .nft 文件逻辑
	nftRules := fmt.Sprintf(`
	table inet singbox_tproxy {
		set RESERVED_IP4 { 
			type ipv4_addr; flags interval; 
			elements = { 100.64.0.0/10, 127.0.0.0/8, 10.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4, 255.255.255.255/32 } 
		}

		chain prerouting {
			type filter hook prerouting priority mangle; policy accept;
			
			# 排除保留地址
			ip daddr @RESERVED_IP4 return
			%s

			# 排除局域网 DNS 以外的流量
			ip daddr %s tcp dport != 53 return
			ip daddr %s udp dport != 53 return

			# TProxy 核心规则
			meta l4proto { tcp, udp } tproxy to :%s meta mark set 1
		}

		chain output {
			type route hook output priority mangle; policy accept;
			
			# 排除保留地址
			ip daddr @RESERVED_IP4 return
			%s

			# 防止环路 (7893 十进制 = 0x1ed5)
			meta mark 0x00001ed5 return
			meta mark 1 return

			# 标记剩余流量
			meta l4proto { tcp, udp } meta mark set 1
		}
	}`, v6Bypass, lan, lan, port, v6Bypass)

	if err := os.WriteFile("/tmp/sb.nft", []byte(nftRules), 0644); err != nil {
		return err
	}
	if err := exec.Command("nft", "-f", "/tmp/sb.nft").Run(); err != nil {
		return fmt.Errorf("nft 加载失败: %v", err)
	}

	// 加载策略路由 (IPv4)
	exec.Command("ip", "rule", "add", "fwmark", "1", "lookup", "100").Run()
	exec.Command("ip", "route", "add", "local", "default", "dev", "lo", "table", "100").Run()
	
	// 加载策略路由 (IPv6)
	if ipv6Mode == "enable" {
		exec.Command("ip", "-6", "rule", "add", "fwmark", "1", "lookup", "100").Run()
		exec.Command("ip", "-6", "route", "add", "local", "default", "dev", "lo", "table", "100").Run()
	}
	return nil
}

func cleanupNetwork() {
	// 强制删除所有可能的旧表名，防止干扰
	exec.Command("nft", "delete", "table", "inet", "singbox_tproxy").Run()
	exec.Command("nft", "delete", "table", "inet", "singbox").Run()
	exec.Command("nft", "delete", "table", "ip", "singbox").Run()
	
	// 循环多次尝试删除策略路由，彻底解决 ip rule 堆叠重复问题
	for i := 0; i < 3; i++ {
		exec.Command("ip", "rule", "del", "fwmark", "1", "lookup", "100").Run()
		exec.Command("ip", "route", "del", "local", "default", "dev", "lo", "table", "100").Run()
		exec.Command("ip", "-6", "rule", "del", "fwmark", "1", "lookup", "100").Run()
		exec.Command("ip", "-6", "route", "del", "local", "default", "dev", "lo", "table", "100").Run()
	}
}

func cleanup() {
	// 1. 杀掉内核进程
	exec.Command("killall", "-9", "sing-box").Run()
	// 2. 清理网络规则
	cleanupNetwork()
}
