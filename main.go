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

type SBConfig struct {
	Inbounds []struct {
		Type   string `json:"type"`
		Listen int    `json:"listen_port"`
	} `json:"inbounds"`
}

func main() {
	lan := flag.String("lan", "", "内网网段 (例: 192.168.31.0/24)")
	ipv6Mode := flag.String("ipv6", "disable", "IPv6 模式: enable 或 disable")
	configPath := flag.String("c", "", "config.json 路径")
	flag.Parse()

	if *lan == "" || *configPath == "" {
		fmt.Println("用法: sudo ./sing-box-tproxy --lan 192.168.31.0/24 --ipv6 disable -c config.json")
		os.Exit(1)
	}

	ensureNftables()
	ensureSingBox()

	port := getTProxyPort(*configPath)
	cleanup()

	if err := setup(*lan, *ipv6Mode, port); err != nil {
		log.Fatalf("规则应用失败: %v", err)
	}

	// 启动核心进程
	cmd := exec.Command("/usr/bin/sing-box", "run", "-c", *configPath)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := cmd.Start(); err != nil { log.Fatalf("运行失败: %v", err) }
		cmd.Wait()
		sigChan <- syscall.SIGTERM
	}()

	<-sigChan
	fmt.Println("\n[-] 收到退出信号，正在清理环境...")
	cleanup()
}

func ensureSingBox() {
	target := "/usr/bin/sing-box"
	if _, err := os.Stat(target); err == nil { return }

	fmt.Println("[!] 正在下载最新 sing-box 核心...")
	arch := runtime.GOARCH
	// 动态匹配架构名
	ver := "1.10.1"
	url := fmt.Sprintf("https://github.com/SagerNet/sing-box/releases/download/v%s/sing-box-%s-linux-%s.tar.gz", ver, ver, arch)

	resp, err := http.Get(url)
	if err != nil { log.Fatal("网络故障，下载核心失败") }
	defer resp.Body.Close()

	gr, _ := gzip.NewReader(resp.Body)
	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF { break }
		if strings.HasSuffix(hdr.Name, "/sing-box") {
			f, _ := os.OpenFile(target, os.O_CREATE|os.O_WRONLY, 0755)
			io.Copy(f, tr)
			f.Close()
			return
		}
	}
}

func ensureNftables() {
	if _, err := exec.LookPath("nft"); err != nil {
		fmt.Println("[!] 自动安装 nftables...")
		exec.Command("apt-get", "update").Run()
		exec.Command("apt-get", "install", "-y", "nftables").Run()
	}
	exec.Command("systemctl", "enable", "--now", "nftables").Run()
}

func getTProxyPort(path string) string {
	f, err := os.ReadFile(path)
	if err != nil { log.Fatal("读取 config.json 失败") }
	var cfg SBConfig
	json.Unmarshal(f, &cfg)
	for _, in := range cfg.Inbounds {
		if in.Type == "tproxy" { return fmt.Sprintf("%d", in.Listen) }
	}
	return "7893"
}

func setup(lan, ipv6, port string) error {
	// 参考了你上传的 sing-box.nft
	nftRules := fmt.Sprintf(`
	table inet singbox_tproxy {
		set reserved_ip4 { type ipv4_addr; flags interval; elements = { 100.64.0.0/10, 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } }
		chain prerouting {
			type filter hook prerouting priority mangle; policy accept;
			ip daddr @reserved_ip4 return
			ip daddr %s return
			meta l4proto { tcp, udp } tproxy to :%s meta mark set 1
		}
		chain output {
			type route hook output priority mangle; policy accept;
			meta mark 1 return
			meta l4proto { tcp, udp } meta mark set 1
		}
	}`, lan, port)

	os.WriteFile("/tmp/sb.nft", []byte(nftRules), 0644)
	if out, err := exec.Command("nft", "-f", "/tmp/sb.nft").CombinedOutput(); err != nil {
		return fmt.Errorf("%s", string(out))
	}
	// 参考了你上传的 tproxy.sh
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
