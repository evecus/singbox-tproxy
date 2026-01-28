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
	lan := flag.String("lan", "", "内网网段 (例: 10.0.0.0/24)")
	configPath := flag.String("c", "", "配置文件路径")
	flag.Parse()

	if *lan == "" || *configPath == "" {
		fmt.Println("用法: sudo ./sing-box-tproxy --lan 10.0.0.0/24 -c config.json")
		os.Exit(1)
	}

	// 1. 强制安装/更新核心到 /usr/bin/sing-box
	syncSingBox()

	// 2. 清理旧规则并应用新规则
	cleanup()
	port := getTProxyPort(*configPath)
	if err := setupRules(*lan, port); err != nil {
		log.Fatalf("规则设置失败: %v", err)
	}

	// 3. 运行核心
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

	fmt.Printf("[+] 透明代理运行中。核心路径: %s\n", targetPath)
	<-sigChan
	cleanup()
}

func syncSingBox() {
	// 获取 GitHub 最新版本号
	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	resp, _ := client.Get("https://github.com/SagerNet/sing-box/releases/latest")
	loc := resp.Header.Get("Location")
	latestVer := loc[strings.LastIndex(loc, "/v")+2:]

	// 检查当前 /usr/bin/sing-box 是否已经是最新版
	if _, err := os.Stat(targetPath); err == nil {
		out, _ := exec.Command(targetPath, "version").Output()
		if strings.Contains(string(out), latestVer) {
			fmt.Println("[+] /usr/bin/sing-box 已经是最新版本 v" + latestVer)
			return
		}
	}

	fmt.Printf("[!] 正在强制下载并安装最新核心 v%s 到 %s...\n", latestVer, targetPath)
	arch := runtime.GOARCH
	url := fmt.Sprintf("https://github.com/SagerNet/sing-box/releases/download/v%s/sing-box-%s-linux-%s.tar.gz", latestVer, latestVer, arch)
	
	dResp, _ := http.Get(url)
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
	file, _ := os.ReadFile(path)
	var cfg Config
	json.Unmarshal(file, &cfg)
	for _, in := range cfg.Inbounds {
		if in.Type == "tproxy" { return fmt.Sprintf("%d", in.Listen) }
	}
	return "7893"
}

func setupRules(lan, port string) error {
	// 重点：在 output 链也加入对保留地址的排除
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
			# 解决断网的关键：机器发出的回程包必须排除在打标范围外
			ip daddr @RESERVED_IP return
			ip daddr %s return
			meta mark 1 return
			meta l4proto { tcp, udp } meta mark set 1
		}
	}`, lan, port, lan)

	os.WriteFile("/tmp/sb.nft", []byte(nftRules), 0644)
	exec.Command("nft", "-f", "/tmp/sb.nft").Run()
	exec.Command("ip", "rule", "add", "fwmark", "1", "lookup", "100").Run()
	exec.Command("ip", "route", "add", "local", "default", "dev", "lo", "table", "100").Run()
	return nil
}

func cleanup() {
	fmt.Println("[-] 清理规则...")
	exec.Command("nft", "delete", "table", "inet", "singbox_tproxy").Run()
	exec.Command("ip", "rule", "del", "fwmark", "1", "lookup", "100").Run()
	exec.Command("ip", "route", "del", "local", "default", "dev", "lo", "table", "100").Run()
}
