package main

import (
	"embed"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/tidwall/gjson"
	"github.com/urfave/cli/v2"
)

//go:embed bin/sing-box-*
var boxEmbed embed.FS

const (
	TableName    = "sb_tproxy_master"
	RouteTable   = 100
	FwMark       = 0x1
	SingBoxPath  = "/usr/bin/sing-box"
)

func main() {
	app := &cli.App{
		Name:  "sb-manager",
		Usage: "Sing-box 旁路由终极管理器",
		Commands: []*cli.Command{
			{
				Name:  "run",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "config", Aliases: []string{"c"}, Required: true},
				},
				Action: runManager,
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func runManager(c *cli.Context) error {
	configPath := c.String("config")

	if os.Geteuid() != 0 {
		return fmt.Errorf("必须以 root 权限运行")
	}

	configData, err := ioutil.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("读取配置失败: %v", err)
	}

	// 1. 自动解析端口 (根据您的配置：TPROXY 7893, DNS 1053)
	tproxyPort := gjson.Get(string(configData), `inbounds.#(type=="tproxy").listen_port`).Int()
	dnsPort := gjson.Get(string(configData), `inbounds.#(tag=="dns-in").listen_port`).Int()
	
	if tproxyPort == 0 { tproxyPort = 7893 }
	if dnsPort == 0 { dnsPort = 1053 }

	// 2. 释放内核
	if err := deploySingBox(); err != nil {
		return err
	}

	// 3. 配置旁路由网络环境 (包含 rp_filter 修复)
	fmt.Printf("[+] 正在同步配置: TPROXY=%d, DNS=%d\n", tproxyPort, dnsPort)
	if err := setupNetwork(int(tproxyPort), int(dnsPort)); err != nil {
		return err
	}

	// 4. 启动内核
	cmd := exec.Command(SingBoxPath, "run", "-c", configPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// 优雅清理
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		fmt.Println("\n[!] 正在清理网络规则并退出...")
		cleanNetwork()
		os.Exit(0)
	}()

	fmt.Println("[*] 旁路由已就绪。请确保手机网关和 DNS 指向本机器。")
	return cmd.Run()
}

func deploySingBox() error {
	embedPath := fmt.Sprintf("bin/sing-box-%s", runtime.GOARCH)
	srcFile, err := boxEmbed.Open(embedPath)
	if err != nil {
		return fmt.Errorf("不支持的架构: %s", runtime.GOARCH)
	}
	defer srcFile.Close()

	os.Remove(SingBoxPath)
	dstFile, err := os.OpenFile(SingBoxPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	return err
}

func setupNetwork(tproxyPort, dnsPort int) error {
	// A. 基础内核参数设置 (解决旁路由丢包核心)
	exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()
	exec.Command("sysctl", "-w", "net.ipv6.conf.all.forwarding=1").Run()

	// B. nftables 规则 (双栈劫持 + NAT 伪装)
	nftScript := fmt.Sprintf(`
		table inet %[1]s {
			set bypass_list_v4 {
				type ipv4_addr; flags interval
				elements = { 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 }
			}
			set bypass_list_v6 {
				type ipv6_addr; flags interval
				elements = { ::1/128, fc00::/7, fe80::/10, ff00::/8 }
			}

			chain prerouting {
				type filter hook prerouting priority mangle; policy accept;

				# 1. DNS 劫持: 强制局域网 53 端口流量进入 Sing-box 的 %[4]d 端口
				udp dport 53 tproxy to :%[4]d accept
				tcp dport 53 tproxy to :%[4]d accept

				# 2. 绕过
				ip daddr @bypass_list_v4 return
				ip6 daddr @bypass_list_v6 return
				meta mark 0xff return

				# 3. 透明代理: 强制进入 Sing-box 的 %[3]d 端口
				meta l4proto { tcp, udp } meta mark set %[2]d tproxy to :%[3]d
			}

			chain output {
				type route hook output priority mangle; policy accept;
				# 本机 DNS 劫持
				udp dport 53 meta mark set %[2]d
				tcp dport 53 meta mark set %[2]d
				ip daddr @bypass_list_v4 return
				ip6 daddr @bypass_list_v6 return
				meta mark 0xff return
				meta l4proto { tcp, udp } meta mark set %[2]d
			}

			chain postrouting {
				type nat hook postrouting priority srcnat; policy accept;
				# 解决回程路由: 将转发流量的源 IP 伪装成旁路由 IP
				ip saddr 10.0.0.0/8 ip daddr != 10.0.0.0/8 masquerade
				ip saddr 172.16.0.0/12 ip daddr != 172.16.0.0/12 masquerade
				ip saddr 192.168.0.0/16 ip daddr != 192.168.0.0/16 masquerade
			}
		}
	`, TableName, FwMark, tproxyPort, dnsPort)

	// C. 执行配置
	cmds := [][]string{
		{"nft", "-f", "-"},
		{"ip", "rule", "add", "fwmark", fmt.Sprintf("%d", FwMark), "table", fmt.Sprintf("%d", RouteTable)},
		{"ip", "route", "add", "local", "default", "dev", "lo", "table", fmt.Sprintf("%d", RouteTable)},
		{"ip", "-6", "rule", "add", "fwmark", fmt.Sprintf("%d", FwMark), "table", fmt.Sprintf("%d", RouteTable)},
		{"ip", "-6", "route", "add", "local", "default", "dev", "lo", "table", fmt.Sprintf("%d", RouteTable)},
	}

	for i, c := range cmds {
		cmd := exec.Command(c[0], c[1:]...)
		if i == 0 {
			stdin, _ := cmd.StdinPipe()
			go func() {
				defer stdin.Close()
				stdin.Write([]byte(nftScript))
			}()
		}
		_ = cmd.Run()
	}
	return nil
}

func cleanNetwork() {
	exec.Command("nft", "delete", "table", "inet", TableName).Run()
	exec.Command("ip", "rule", "del", "fwmark", fmt.Sprintf("%d", FwMark)).Run()
	exec.Command("ip", "route", "del", "local", "default", "table", fmt.Sprintf("%d", RouteTable)).Run()
	exec.Command("ip", "-6", "rule", "del", "fwmark", fmt.Sprintf("%d", FwMark)).Run()
	exec.Command("ip", "-6", "route", "del", "local", "default", "table", fmt.Sprintf("%d", RouteTable)).Run()
}
