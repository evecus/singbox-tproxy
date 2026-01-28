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
	ipv6Mode := flag.String("ipv6", "", "IPv6 模式: 'enable' 或 'disable'")
	configPath := flag.String("c", "", "config.json 路径")
	flag.Parse()

	if *lan == "" || *ipv6Mode == "" || *configPath == "" {
		fmt.Println("用法: sudo ./sing-box-tproxy --lan <网段> --ipv6 <enable|disable> -c <配置文件>")
		os.Exit(1)
	}

	// 1. 环境准备
	ensureNftables()
	ensureSingBox()

	// 2. 解析配置端口
	port := getTProxyPort(*configPath)
	
	// 3. 配置 TProxy 规则
	cleanup()
	if err := setup(*lan, *ipv6Mode, port); err != nil {
		log.Fatalf("网络规则设置失败: %v", err)
	}

	// 4. 运行核心
	cmd := exec.Command("/usr/bin/sing-box", "run", "-c", *configPath)
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
	fmt.Println("\n[-] 正在清理规则并退出...")
	cleanup()
}

func ensureSingBox() {
	target := "/usr/bin/sing-box"
	if _, err := os.Stat(target); err == nil {
		return
	}

	fmt.Println("[!] 未检测到核心，正在从 GitHub 获取最新版本...")
	
	arch := runtime.GOARCH
	// 构造 GitHub 下载链接 (简化版，也可通过 API 获取最新 tag)
	// 示例：https://github.com/SagerNet/sing-box/releases/download/v1.10.1/sing-box-1.10.1-linux-amd64.tar.gz
	version := "1.10.1" // 你可以手动修改此默认版本
	url := fmt.Sprintf("https://github.com/SagerNet/sing-box/releases/download/v%s/sing-box-%s-linux-%s.tar.gz", version, version, arch)

	resp, err := http.Get(url)
	if err != nil {
		log.Fatalf("下载失败: %v", err)
	}
	defer resp.Body.Close()

	if err := extractBinary(resp.Body, target); err != nil {
		log.Fatalf("提取二进制失败: %v", err)
	}
	
	os.Chmod(target, 0755)
	fmt.Println("[+] sing-box 核心下载完成")
}

func extractBinary(r io.Reader, target string) error {
	gr, _ := gzip.NewReader(r)
	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF { break }
		if strings.HasSuffix(hdr.Name, "/sing-box") {
			out, _ := os.Create(target)
			defer out.Close()
			_, err := io.Copy(out, tr)
			return err
		}
	}
	return fmt.Errorf("未在压缩包内找到二进制文件")
}

func ensureNftables() {
	if _, err := exec.LookPath("nft"); err != nil {
		managers := map[string]string{"apt-get": "install -y nftables", "yum": "install -y nftables", "pacman": "-S --noconfirm nftables"}
		for m, args := range managers {
			if _, e := exec.LookPath(m); e == nil {
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
	return "7893"
}

func setup(lan, ipv6, port string) error {
	nftRules := fmt.Sprintf(`
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

	os.WriteFile("/tmp/sb.nft", []byte(nftRules), 0644)
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
