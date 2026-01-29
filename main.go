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
		fmt.Printf("\n[!] 启动失败: 缺少硬性参数\n")
		os.Exit(1)
	}

	// --- 2. 进程与配置预检 (在修改网络前执行) ---
	// 检查是否有 sing-box 进程正在运行
	checkAndKillExistingProcess()
	
	// 检查配置文件是否存在且包含 tproxy 入站
	port := getTProxyPortOrDie(*configPath)

	// --- 3. 准备内核 ---
	tempDir := "/tmp/.sb_runtime"
	os.MkdirAll(tempDir, 0755)
	targetCore := filepath.Join(tempDir, "sing-box")
	os.WriteFile(targetCore, embeddedSingBox, 0755)
	defer os.RemoveAll(tempDir)

	// --- 4. 初始化网络环境 (仅加载一次) ---
	fmt.Println("[*] 正在清理旧规则并部署新规则...")
	if err := setupRules(*lan, *ipv6Mode, port); err != nil {
		fmt.Printf("[!] 规则加载失败: %v\n", err)
		cleanup() // 失败回滚
		os.Exit(1)
	}

	// --- 5. 启动内核 ---
	cmd := exec.Command(targetCore, "run", "-c", *configPath)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	// 父进程死掉时，子进程必死
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	if err := cmd.Start(); err != nil {
		fmt.Printf("[!] Sing-box 启动失败: %v\n", err)
		cleanup()
		os.Exit(1)
	}

	fmt.Printf("[+] 启动成功! IP:%s | IPv6:%s | TProxy:%s\n", *lan, *ipv6Mode, port)

	// --- 6. 运行维护与退出清理 ---
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-sigChan:
		fmt.Println("\n[*] 接收到停止信号，正在清理...")
	case err := <-done:
		fmt.Printf("\n[!] 内核意外停止: %v，正在清理...\n", err)
	}

	cleanup()
	fmt.Println("[+] 环境已还原，程序安全退出。")
}

// 检测并清理现有的 sing-box 进程
func checkAndKillExistingProcess() {
	// 使用 pgrep 查找进程名包含 sing-box 的进程
	out, _ := exec.Command("pgrep", "-f", "sing-box").Output()
	pids := strings.Fields(string(out))
	
	if len(pids) > 0 {
		fmt.Printf("[!] 发现正在运行的 sing-box 进程 (PIDs: %s)，正在清理...\n", strings.Join(pids, ", "))
		// 强制杀死所有现有进程
		exec.Command("killall", "-9", "sing-box").Run()
		// 给系统一点响应时间
		exec.Command("sleep", "0.5").Run()
	}
}

func getTProxyPortOrDie(path string) string {
	file, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("[!] 无法读取配置文件: %v", err)
	}
	var cfg Config
	if err := json.Unmarshal(file, &cfg); err != nil {
		log.Fatalf("[!] 配置文件 JSON 解析失败")
	}
	for _, in := range cfg.Inbounds {
		if in.Type == "tproxy" && in.Listen != 0 {
			return fmt.Sprintf("%d", in.Listen)
		}
	}
	fmt.Println("[!] 配置文件中未检测到 tproxy 入站端口，拒绝启动。")
	os.Exit(1)
	return ""
}

func setupRules(lan, ipv6Mode, port string) error {
	// 部署前强制清理一次网络状态
	cleanupNetwork()

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
		return fmt.Errorf("nft 加载失败")
	}

	// 加载路由
	exec.Command("ip", "rule", "add", "fwmark", "1", "lookup", "100").Run()
	exec.Command("ip", "route", "add", "local", "default", "dev", "lo", "table", "100").Run()
	if ipv6Mode == "enable" {
		exec.Command("ip", "-6", "rule", "add", "fwmark", "1", "lookup", "100").Run()
		exec.Command("ip", "-6", "route", "add", "local", "default", "dev", "lo", "table", "100").Run()
	}
	return nil
}

func cleanupNetwork() {
	// 清理 nft 表
	exec.Command("nft", "delete", "table", "inet", "singbox_tproxy").Run()
	exec.Command("nft", "delete", "table", "inet", "singbox").Run()
	
	// 循环清理策略路由，防止规则堆叠（尝试 3 次）
	for i := 0; i < 3; i++ {
		exec.Command("ip", "rule", "del", "fwmark", "1", "lookup", "100").Run()
		exec.Command("ip", "route", "del", "local", "default", "dev", "lo", "table", "100").Run()
		exec.Command("ip", "-6", "rule", "del", "fwmark", "1", "lookup", "100").Run()
		exec.Command("ip", "-6", "route", "del", "local", "default", "dev", "lo", "table", "100").Run()
	}
}

func cleanup() {
	// 停止所有相关进程
	exec.Command("killall", "-9", "sing-box").Run()
	// 清理网络规则
	cleanupNetwork()
}
