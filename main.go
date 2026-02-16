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
		Usage: "自带内核的 Sing-box 旁路由/TPROXY/DNS 劫持一键工具",
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
		return fmt.Errorf("必须以 root 权限运行，请使用 sudo")
	}

	configData, err := ioutil.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("读取配置文件失败: %v", err)
	}

	// 1. 解析 TPROXY 端口
	tproxyPort := gjson.Get(string(configData), `inbounds.#(type=="tproxy").listen_port`).Int()
	if tproxyPort == 0 {
		return fmt.Errorf("错误: config.json 中未找到 tproxy 类型的 listen_port")
	}

	// 2. 解析 DNS 监听端口 (优先从 inbounds 找，找不到默认劫持到 53)
	dnsPort := gjson.Get(string(configData), `inbounds.#(type=="direct" && tag=="dns-in").listen_port`).Int()
	if dnsPort == 0 {
		dnsPort = 53 // 默认值
	}

	// 3. 释放内核
	if err := deploySingBox(); err != nil {
		return err
	}

	// 4. 配置网络规则 (转发 + DNS 劫持 + TPROXY)
	fmt.Printf("[+] 配置网络 (TPROXY: %d, DNS: %d)...\n", tproxyPort, dnsPort)
	if err := setupNetwork(int(tproxyPort), int(dnsPort)); err != nil {
		return err
	}

	// 5. 启动 sing-box
	cmd := exec.Command(SingBoxPath, "run", "-c", configPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// 优雅清理
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		fmt.Println("\n[!] 正在撤销所有防火墙规则与路由...")
		cleanNetwork()
		os.Exit(0)
	}()

	fmt.Println("[*] 系统已就绪。旁路由模式已激活。")
	return cmd.Run()
}

func deploySingBox() error {
	embedPath := fmt.Sprintf("bin/sing-box-%s", runtime.GOARCH)
	srcFile, err := boxEmbed.Open(embedPath)
	if err != nil {
		return fmt.Errorf("当前架构不支持: %s", runtime.GOARCH)
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
	// A. 开启内核转发
	exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()
	exec.Command("sysctl", "-w", "net.ipv6.conf.all.forwarding=1").Run()

	// B. nftables 混合表配置 (IPv4 + IPv6)
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

				# 1. DNS 劫持 (局域网设备请求)
				udp dport 53 tproxy to :%[4]d accept
				tcp dport 53 tproxy to :%[4]d accept

				# 2. 绕过保留地址
				ip daddr @bypass_list_v4 return
				ip6 daddr @bypass_list_v6 return

				# 3. 绕过 Sing-box 自身的出站标记 (0xff)
				meta mark 0xff return

				# 4. TPROXY 透明代理
				meta l4proto { tcp, udp } meta mark set %[2]d tproxy to :%[3]d
			}
			chain output {
				type route hook output priority mangle; policy accept;

				# 1. DNS 劫持 (本机请求)
				udp dport 53 meta mark set %[2]d
				tcp dport 53 meta mark set %[2]d

				# 2. 绕过保留地址与自身标记
				ip daddr @bypass_list_v4 return
				ip6 daddr @bypass_list_v6 return
				meta mark 0xff return

				# 3. 本机流量打标以便路由重定向
				meta l4proto { tcp, udp } meta mark set %[2]d
			}
		}
	`, TableName, FwMark, tproxyPort, dnsPort)

	// C. 应用配置命令
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
