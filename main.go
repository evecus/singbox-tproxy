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
	lan := flag.String("lan", "", "IPv4 内网网段 (必填)")
	ipv6Mode := flag.String("ipv6", "", "IPv6 模式 (必填: enable | disable)")
	configPath := flag.String("c", "", "配置文件路径 (必填)")
	flag.Parse()

	// --- 1. 参数检测 ---
	if *lan == "" || *configPath == "" || *ipv6Mode == "" {
		fmt.Printf("\n[!] 启动失败: 参数不完整\n用法: sudo ./sing-box-tproxy --lan %s --ipv6 %s -c %s\n", "10.0.0.0/24", "disable", "config.json")
		os.Exit(1)
	}
	if *ipv6Mode != "enable" && *ipv6Mode != "disable" {
		log.Fatalf("[!] 错误: --ipv6 参数非法")
	}

	// --- 2. 配置文件与端口检测 ---
	// 如果检测失败，函数内部会直接 os.Exit(1)，不触发任何规则加载
	port := getTProxyPortOrDie(*configPath)

	// --- 3. 释放内核 (准备工作) ---
	tempDir := "/tmp/.sb_runtime"
	os.MkdirAll(tempDir, 0755)
	targetCore := filepath.Join(tempDir, "sing-box")
	if err := os.WriteFile(targetCore, embeddedSingBox, 0755); err != nil {
		log.Fatalf("[!] 内核释放失败: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// --- 4. 加载网络规则 (仅加载一次) ---
	// 在加载前先清空可能存在的旧残留，确保环境纯净
	cleanup() 
	fmt.Println("[*] 正在加载网络规则与策略路由...")
	if err := setupRules(*lan, *ipv6Mode, port); err != nil {
		fmt.Printf("[!] 网络规则加载失败: %v，程序终止。\n", err)
		cleanup() // 失败回滚
		os.Exit(1)
	}

	// --- 5. 启动 Sing-box ---
	cmd := exec.Command(targetCore, "run", "-c", *configPath)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	// 确保父进程意外死亡时，内核也自杀
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}

	// 捕获退出信号 (Ctrl+C 或 Systemd Stop)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	if err := cmd.Start(); err != nil {
		fmt.Printf("[!] Sing-box 启动失败: %v，正在回滚网络规则...\n", err)
		cleanup()
		os.Exit(1)
	}

	fmt.Printf("[+] 所有流程执行成功！\n[+] TProxy 运行中 (端口: %s)\n", port)

	// 监听进程状态：如果内核中途崩溃，也触发清理
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	// 阻塞直到收到信号或内核退出
	select {
	case <-sigChan:
		fmt.Println("\n[!] 接收到退出信号...")
	case err := <-done:
		if err != nil {
			fmt.Printf("\n[!] 内核异常退出: %v\n", err)
		} else {
			fmt.Println("\n[!] 内核已停止运行")
		}
	}

	// --- 6. 最终清理 ---
	cleanup()
	fmt.Println("[+] 规则已清空，进程已杀灭。")
}

func getTProxyPortOrDie(path string) string {
	file, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("[!] 无法读取配置文件: %v", err)
	}
	var cfg Config
	json.Unmarshal(file, &cfg)
	for _, in := range cfg.Inbounds {
		if in.Type == "tproxy" && in.Listen != 0 {
			return fmt.Sprintf("%d", in.Listen)
		}
	}
	fmt.Println("[!] 配置文件中未发现有效 tproxy 入站，拒绝执行。")
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
			elements = { 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } 
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

	if err := os.WriteFile("/tmp/sb.nft", []byte(nftRules), 0644); err != nil {
		return err
	}
	if err := exec.Command("nft", "-f", "/tmp/sb.nft").Run(); err != nil {
		return err
	}

	// 策略路由
	exec.Command("ip", "rule", "add", "fwmark", "1", "lookup", "100").Run()
	exec.Command("ip", "route", "add", "local", "default", "dev", "lo", "table", "100").Run()
	if ipv6Mode == "enable" {
		exec.Command("ip", "-6", "rule", "add", "fwmark", "1", "lookup", "100").Run()
		exec.Command("ip", "-6", "route", "add", "local", "default", "dev", "lo", "table", "100").Run()
	}
	return nil
}

func cleanup() {
	// 1. 杀进程
	exec.Command("killall", "-9", "sing-box").Run()
	// 2. 清理 nft 表
	exec.Command("nft", "delete", "table", "inet", "singbox_tproxy").Run()
	exec.Command("nft", "delete", "table", "inet", "singbox").Run()
	// 3. 循环清理路由和规则 (v4 & v6)
	for _, family := range []string{"-4", "-6"} {
		exec.Command("ip", family, "rule", "del", "fwmark", "1", "lookup", "100").Run()
		exec.Command("ip", family, "route", "del", "local", "default", "dev", "lo", "table", "100").Run()
	}
}
