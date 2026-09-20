package main

import (
	"fmt"
	"go/format"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/gospider007/tools"
)

// 本工具把上游 uTLS（github.com/refraction-networking/utls）整体内联进 ja3 仓库，
// 改造成本地子包 github.com/gospider007/ja3/utls，并打上业务所需的代码补丁。
//
// 升级/重装 utls 的标准流程：
//
//	rm -rf ./utls && git clone https://github.com/refraction-networking/utls.git
//	go run ./cmd/path.go
//
// 脚本依次做三件事：
//
//  1. 删除 utls/go.mod、utls/go.sum —— 让 utls 归属 ja3 模块。否则它是一个独立模块，
//     ja3 只能通过 require/replace 引用它，无法把它当子包。
//  2. 全局改写 import 前缀：
//     github.com/refraction-networking/utls → github.com/gospider007/ja3/utls
//     这一步是必须的。Go 规定 internal/ 包只对「同一模块前缀」内的代码可见，
//     前缀不改就会出现大量 “use of internal package ... not allowed” 爆红。
//     只匹配带引号的 import 路径，注释里的 GitHub URL 不受影响。
//  3. 按 patchList 打业务补丁。补丁是幂等的：已打过就跳过；锚点找不到（上游代码变更）
//     只打印提示，不 panic。
//
// 注意：本脚本必须能在「干净的 utls 源码」上跑，所以不要依赖已经被改写过的内容。

// 模块路径改写的前后缀。带引号匹配，确保只命中 import 行，
// 不会误伤注释里的 https://github.com/refraction-networking/utls 链接。
const (
	moduleOld = `"github.com/refraction-networking/utls`
	moduleNew = `"github.com/gospider007/ja3/utls`
)

// patch 描述一处代码补丁。
type patch struct {
	name string // 补丁名称，用于日志
	file string // 相对 utls 目录的文件路径（用 / 分隔）
	old  string // 原始代码锚点，必须与上游文本逐字符一致（含制表符缩进）
	new  string // 替换后的代码
}

// patchList 是全部补丁清单。新增补丁往这里加即可。
var patchList = []patch{
	{
		name: "忽略服务端证书解析失败",
		file: "handshake_client.go",
		// 上游行为：证书 DER 解析失败 → 发 alert 并中断握手。
		// 实际问题：部分站点返回畸形/特殊曲线的证书（x509 不支持的椭圆曲线），
		// 直接判错会导致连不上，无法做指纹测试或抓包。
		// 补丁行为：解析失败时构造一个占位证书继续握手。后续 RSA 长度检查不会命中，
		// 因为占位证书的 PublicKeyAlgorithm 不是 x509.RSA。
		//
		// 关于 &ecdsa.PublicKey{Curve: &ecdsa.PublicKey{}} 为何能编译：
		// crypto/ecdsa.PublicKey 内嵌了 elliptic.Curve 接口，方法集被提升，
		// 因此 *ecdsa.PublicKey 满足 elliptic.Curve 约束。
		// 运行时不会调用它的 Curve 方法，所以嵌套的 nil 曲线不会 panic。
		old: `		cert, err := globalCertCache.newCert(asn1Data)
		if err != nil {
			c.sendAlert(alertBadCertificate)
			return errors.New("tls: failed to parse certificate from server: " + err.Error())
		}`,
		new: `		cert, err := globalCertCache.newCert(asn1Data)
		if err != nil {
			cert = &activeCert{cert: &x509.Certificate{PublicKey: &ecdsa.PublicKey{Curve: &ecdsa.PublicKey{}}}}
		}`,
	},
}

func main() {
	// cmd/path.go → ja3 目录 → utls 目录
	_, currentFile, _, _ := runtime.Caller(0)
	utlsDir := filepath.Join(filepath.Dir(currentFile), "..", "utls")
	if !tools.PathExist(utlsDir) {
		log.Panicf("utls 目录不存在，请先 clone：%s", utlsDir)
	}

	removeSubModule(utlsDir)

	files, count := rewriteImports(utlsDir)
	log.Printf("import 前缀改写完成：%d 个文件，共 %d 处", files, count)

	applyPatches(utlsDir)

	log.Print("全部完成")
}

// removeSubModule 删除 utls 自带的 go.mod / go.sum，
// 让 utls 目录归属 ja3 模块（否则它会被当成独立模块，无法作为子包被引用）。
func removeSubModule(utlsDir string) {
	for _, name := range []string{"go.mod", "go.sum"} {
		path := filepath.Join(utlsDir, name)
		if !tools.PathExist(path) {
			continue
		}
		if err := os.Remove(path); err != nil {
			log.Panic(err)
		}
		log.Printf("已删除 %s", name)
	}
}

// rewriteImports 遍历 utls 下所有 .go 文件，把上游模块前缀改写成本地前缀。
// 返回被修改的文件数与替换处数。
func rewriteImports(utlsDir string) (files, replaced int) {
	err := filepath.WalkDir(utlsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// 跳过 .git 等隐藏目录，避免改写仓库元数据
			if path != utlsDir && strings.HasPrefix(d.Name(), ".") {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		code := string(content)
		if !strings.Contains(code, moduleOld) {
			return nil
		}
		if err := writeGoFile(path, strings.ReplaceAll(code, moduleOld, moduleNew)); err != nil {
			return err
		}
		files++
		replaced += strings.Count(code, moduleOld)
		return nil
	})
	if err != nil {
		log.Panic(err)
	}
	return files, replaced
}

// applyPatches 依次应用 patchList，幂等执行。
func applyPatches(utlsDir string) {
	for _, p := range patchList {
		path := filepath.Join(utlsDir, filepath.FromSlash(p.file))
		content, err := os.ReadFile(path)
		if err != nil {
			log.Panicf("[%s] 读取 %s 失败：%v", p.name, p.file, err)
		}
		code := string(content)

		if strings.Contains(code, p.new) {
			log.Printf("[%s] 已打过补丁，跳过", p.name)
			continue
		}
		if !strings.Contains(code, p.old) {
			// 上游代码结构变化（例如升级了 utls 版本）。此处不 panic，
			// 只提示人工确认，避免脚本被卡死。
			log.Printf("[%s] 未找到原始代码锚点（%s），请人工确认上游是否已变更", p.name, p.file)
			continue
		}
		if err := writeGoFile(path, strings.Replace(code, p.old, p.new, 1)); err != nil {
			log.Panicf("[%s] 写入 %s 失败：%v", p.name, p.file, err)
		}
		log.Printf("[%s] 补丁已应用", p.name)
	}
}

// writeGoFile 用 gofmt 格式化后写回；格式化失败则按原样写入，不中断脚本。
func writeGoFile(path, code string) error {
	if formatted, err := format.Source([]byte(code)); err == nil {
		code = string(formatted)
	} else {
		log.Printf("gofmt 失败，按原样写入 %s：%v", path, err)
	}
	if err := os.WriteFile(path, []byte(code), 0644); err != nil {
		return fmt.Errorf("写入 %s: %w", path, err)
	}
	return nil
}
