package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/tidwall/gjson"
)

// AutoNetworkManager 处理网络配置
func AutoNetworkManager(configPath string) {
	// 排除非 root 和 帮助命令
	if os.Geteuid() != 0 || (len(os.Args) > 1 && (os.Args[1] == "version" || os.Args[1] == "help")) {
		return
	}

	lan := "10.0.0.0/24"
	var tproxyPort, dnsPort int64 = 7893, 1053

	// 读取配置文件提取端口
	content, err := os.ReadFile(configPath)
	if err == nil {
		t := gjson.Get(string(content), `inbounds.#(type=="tproxy").listen_port`).Int()
		if t != 0 { tproxyPort = t }
		d := gjson.Get(string(content), `inbounds.#(tag=="dns-in").listen_port`).Int()
		if d != 0 { dnsPort = d }
	}

	fmt.Printf("[+] 旁路由模式启动: LAN=%s, TPROXY=%d, DNS=%d\n", lan, tproxyPort, dnsPort)

	// 配置网络
	setup(tproxyPort, dnsPort, lan)

	// 监听信号清理退出
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		fmt.Println("\n[!] 正在清理网络规则...")
		cleanup(lan)
		os.Exit(0)
	}()
}

func setup(tPort, dPort int64, lan string) {
	exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()
	exec.Command("sysctl", "-w", "net.ipv4.conf.all.rp_filter=0").Run()
	exec.Command("sysctl", "-w", "net.ipv4.conf.default.rp_filter=0").Run()

	nft := fmt.Sprintf(`
define RESERVED_IP4 = { 100.64.0.0/10, 127.0.0.0/8, 10.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4, 255.255.255.255/32 }
define RESERVED_IP6 = { ::/128, ::1/128, ::ffff:0:0/96, 64:ff9b::/96, 100::/64, 2001::/32, 2001:20::/28, 2001:db8::/32, 2002::/16, fc00::/7, fe80::/10, ff00::/8 }
table inet singbox_auto {
    chain prerouting {
        type filter hook prerouting priority mangle; policy accept;
        udp dport 53 tproxy to :%[2]d accept
        tcp dport 53 tproxy to :%[2]d accept
        ip daddr $RESERVED_IP4 return
        ip6 daddr $RESERVED_IP6 return
        ip daddr %[3]s tcp dport != 53 return
        ip daddr %[3]s udp dport != 53 return
        meta l4proto { tcp, udp } tproxy to :%[1]d meta mark set 1
    }
    chain output {
        type route hook output priority mangle; policy accept;
        ip daddr $RESERVED_IP4 return
        ip6 daddr $RESERVED_IP6 return
        meta mark 0xff return
        meta l4proto { tcp, udp } meta mark set 1
    }
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        ip saddr %[3]s masquerade
    }
}`, tPort, dPort, lan)

	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(nft)
	cmd.Run()

	exec.Command("ip", "rule", "add", "fwmark", "1", "table", "100").Run()
	exec.Command("ip", "route", "add", "local", "default", "dev", "lo", "table", "100").Run()
}

func cleanup(lan string) {
	exec.Command("nft", "delete", "table", "inet", "singbox_auto").Run()
	exec.Command("ip", "rule", "del", "fwmark", "1", "table", "100").Run()
	exec.Command("ip", "route", "del", "local", "default", "dev", "lo", "table", "100").Run()
}
