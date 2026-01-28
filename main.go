package main

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
)

type Config struct {
	Inbounds []struct {
		Type   string `json:"type"`
		Listen int    `json:"listen_port"`
	} `json:"inbounds"`
}

const targetPath = "/usr/bin/sing-box"

func main() {
	// 重新定义并补全所有 flag
	lan := flag.String("lan", "", "内网网段 (例: 10.0.0.0/24)")
	ipv6Mode := flag.String("ipv6", "disable", "IPv6 模式: enable 或 disable")
	configPath := flag.String("c", "", "配置文件路径")
	flag.Parse()

	if *lan == "" || *configPath == "" {
		fmt.Println("用法: sudo ./sing-box-tproxy --lan 10.0.0.0/24 --ipv6 disable -c config.json")
		os.Exit(1)
	}

	// 1. 强制检查/下载最新核心到 /usr/bin/sing-box
	syncSingBox()

	// 2. 清理环境并应用 nftables 规则
	cleanup()
	port := getTProxyPort(*configPath)
	if err := setupRules(*lan, *ipv6Mode, port); err != nil {
		log.Fatalf("规则设置失败: %v", err)
	}

	// 3. 启动核心
	cmd := exec.Command(targetPath, "run", "-c", *configPath)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := cmd.Start(); err != nil {
			log.Fatalf("核心启动失败: %v", err)
		}
		cmd.Wait()
		sigChan <- syscall.SIGTERM
	}()

	fmt.Printf("[+] 代理运行中。LAN: %s, IPv6: %s, 端口: %s\n", *lan, *ipv6Mode, port)
	<-sigChan
	cleanup()
}

func syncSingBox() {
	// 获取最新版本
	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get("https://github.com/SagerNet/sing-box/releases/latest")
	if err != nil {
		fmt.Println("[!] 无法连接 GitHub，跳过更新检测")
		return
	}
	loc := resp.Header.Get("Location")
	latestVer := loc[strings.LastIndex(loc, "/v")+2:]

	// 检查本地版本
	if _, err := os.Stat(targetPath); err == nil {
		out, _ := exec.Command(targetPath, "version").Output()
		if strings.Contains(string(out), latestVer) {
			fmt.Println("[+] 核心已是最新版本 v" + latestVer)
			return
		}
	}

	fmt.Printf("[!] 正在安装最新核心 v%s 到 %s...\n", latestVer, targetPath)
	arch := runtime.GOARCH
	url := fmt.Sprintf("https://github.com/SagerNet/sing-box/releases/download/v%s/sing-box-%s-linux-%s.tar.gz", latestVer, latestVer, arch)
	
	dResp, err := http.Get(url)
	if err != nil { log.Fatal("下载失败") }
	defer dResp.Body.Close()

	gr, _ := gzip.NewReader(dResp.Body)
	tr := tar.NewReader(gr)
	for {
		hdr, _ := tr.Next()
		if strings.HasSuffix(hdr.Name, "/sing-box") {
			f, _ := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
			io.Copy(f, tr)
			f.Close()
			break
		}
	}
}

func getTProxyPort(path string) string {
	file, err := os.ReadFile(path)
	if err != nil { return "7893" }
	var cfg Config
	json.Unmarshal(file, &cfg)
	for _, in := range cfg.Inbounds {
		if in.Type == "tproxy" { return fmt.Sprintf("%d", in.Listen) }
	}
	return "7893"
}

func setupRules(lan, ipv6, port string) error {
	// 修复逻辑：在 output 链同步排除保留地址和内网网段
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
		return fmt.Errorf("nftables 加载失败")
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
	fmt.Println("[-] 清理规则并还原网络...")
	exec.Command("nft", "delete", "table", "inet", "singbox_tproxy").Run()
	exec.Command("ip", "rule", "del", "fwmark", "1", "lookup", "100").Run()
	exec.Command("ip", "route", "del", "local", "default", "dev", "lo", "table", "100").Run()
	exec.Command("ip", "-6", "rule", "del", "fwmark", "1", "lookup", "100").Run()
	exec.Command("ip", "-6", "route", "del", "local", "default", "dev", "lo", "table", "100").Run()
}
