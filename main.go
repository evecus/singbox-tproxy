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
	TableName    = "sb_tproxy_rules"
	RouteTable   = 100
	FwMark       = 0x1
	SingBoxPath  = "/usr/bin/sing-box"
)

func main() {
	app := &cli.App{
		Name:  "sb-manager",
		Usage: "自带内核的 Sing-box 旁路由/TPROXY 一键工具",
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

	// 1. 检查权限
	if os.Geteuid() != 0 {
		return fmt.Errorf("必须以 root 权限运行，请使用 sudo")
	}

	// 2. 解析配置文件
	configData, err := ioutil.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("读取配置文件失败: %v", err)
	}
	tproxyPort := gjson.Get(string(configData), `inbounds.#(type=="tproxy").listen_port`).Int()
	if tproxyPort == 0 {
		return fmt.Errorf("错误: config.json 中未找到 tproxy 类型的 listen_port")
	}

	// 3. 释放内核文件
	fmt.Printf("正在释放内核至 %s...\n", SingBoxPath)
	if err := deploySingBox(); err != nil {
		return err
	}

	// 4. 配置旁路由网络环境 (转发 + 路由 + nftables)
	fmt.Printf("正在配置旁路由网络规则 (端口: %d)...\n", tproxyPort)
	if err := setupNetwork(int(tproxyPort)); err != nil {
		return err
	}

	// 5. 启动内核
	cmd := exec.Command(SingBoxPath, "run", "-c", configPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// 优雅退出处理
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		fmt.Println("\n[!] 收到信号，正在清理网络规则...")
		cleanNetwork()
		os.Exit(0)
	}()

	fmt.Println("[*] Sing-box 已启动。局域网设备请将网关设置为本机器 IP。")
	return cmd.Run()
}

func deploySingBox() error {
	embedPath := fmt.Sprintf("bin/sing-box-%s", runtime.GOARCH)
	srcFile, err := boxEmbed.Open(embedPath)
	if err != nil {
		return fmt.Errorf("不支持的架构: %s", runtime.GOARCH)
	}
	defer srcFile.Close()

	// 强制替换旧文件
	os.Remove(SingBoxPath)
	dstFile, err := os.OpenFile(SingBoxPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return fmt.Errorf("无法写入 /usr/bin: %v", err)
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	return err
}

func setupNetwork(port int) error {
	// A. 开启内核转发（旁路由核心）
	exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()
	exec.Command("sysctl", "-w", "net.ipv6.conf.all.forwarding=1").Run()

	// B. 构建 nftables 脚本 (支持双栈且跳过保留地址)
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
				# 排除保留地址
				ip daddr @bypass_list_v4 return
				ip6 daddr @bypass_list_v6 return
				# 排除自身流量标记 (防止回环)
				meta mark 0xff return
				# 透明代理 TCP & UDP
				meta l4proto { tcp, udp } meta mark set %[2]d tproxy to :%[3]d
			}
			chain output {
				type route hook output priority mangle; policy accept;
				# 排除保留地址
				ip daddr @bypass_list_v4 return
				ip6 daddr @bypass_list_v6 return
				# 排除自身流量标记
				meta mark 0xff return
				# 对本机流量打标以便路由重定向
				meta l4proto { tcp, udp } meta mark set %[2]d
			}
		}
	`, TableName, FwMark, port)

	// C. 执行命令序列
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
	// 清理 nftables 表
	exec.Command("nft", "delete", "table", "inet", TableName).Run()
	// 清理 IPv4 路由
	exec.Command("ip", "rule", "del", "fwmark", fmt.Sprintf("%d", FwMark)).Run()
	exec.Command("ip", "route", "del", "local", "default", "table", fmt.Sprintf("%d", RouteTable)).Run()
	// 清理 IPv6 路由
	exec.Command("ip", "-6", "rule", "del", "fwmark", fmt.Sprintf("%d", FwMark)).Run()
	exec.Command("ip", "-6", "route", "del", "local", "default", "table", fmt.Sprintf("%d", RouteTable)).Run()
}
