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
	TableName    = "sb_tproxy"
	RouteTable   = 100
	FwMark       = 0x1
	SingBoxPath  = "/usr/bin/sing-box"
)

func main() {
	app := &cli.App{
		Name:  "sb-manager",
		Usage: "自带内核并自动安装的 Sing-box TPROXY 管理器",
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
		return fmt.Errorf("请使用 sudo 或 root 权限运行此程序")
	}

	configData, err := ioutil.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("读取配置失败: %v", err)
	}
	tproxyPort := gjson.Get(string(configData), `inbounds.#(type=="tproxy").listen_port`).Int()
	if tproxyPort == 0 {
		return fmt.Errorf("配置错误: 未在 inbounds 中找到 type: tproxy 的 listen_port")
	}

	if err := deploySingBox(); err != nil {
		return fmt.Errorf("部署内核失败: %v", err)
	}

	fmt.Printf("正在配置网络规则 (TPROXY Port: %d)... ", tproxyPort)
	if err := setupNetwork(int(tproxyPort)); err != nil {
		return err
	}
	fmt.Println("成功")

	cmd := exec.Command(SingBoxPath, "run", "-c", configPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		fmt.Println("\n正在清理网络规则并停止内核...")
		cleanNetwork()
		os.Exit(0)
	}()

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
		return fmt.Errorf("无法写入 /usr/bin: %v (尝试 sudo)", err)
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	return err
}

func setupNetwork(port int) error {
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
				ip daddr @bypass_list_v4 return
				ip6 daddr @bypass_list_v6 return
				meta l4proto { tcp, udp } meta mark set %[2]d tproxy to :%[3]d
			}
		}
	`, TableName, FwMark, port)

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
