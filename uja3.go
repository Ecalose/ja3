package ja3

import (
	"errors"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	uquic "github.com/refraction-networking/uquic"
)

type USpec struct {
	QUICID uquic.QUICID
}

func (obj USpec) Spec() (uquic.QUICSpec, error) {
	spec, err := uquic.QUICID2Spec(obj.QUICID)
	if err != nil {
		return uquic.QUICSpec{}, err
	}
	return spec, nil
}
func CreateUSpec(value any) (uquic.QUICSpec, error) {
	switch data := value.(type) {
	case bool:
		if data {
			return uquic.QUICID2Spec(uquic.QUICFirefox_116)
		}
		return uquic.QUICSpec{}, nil
	case uquic.QUICID:
		return uquic.QUICID2Spec(data)
	case USpec:
		return data.Spec()
	default:
		return uquic.QUICSpec{}, errors.New("unsupported type")
	}
}

// Patch 自动给 utls/conn.go 打补丁，绕过 x509 不支持椭圆曲线的错误
func Patch() {
	// ✅ 获取【当前文件（patch.go）】的绝对路径
	_, currentFile, _, _ := runtime.Caller(0)

	// ✅ 获取 ja3 目录的绝对路径
	jaDir := filepath.Dir(currentFile)

	// ✅ 拼接出 utls/handshake_client.go 绝对路径
	// 目录结构： ja3/../utls
	utlsPath := filepath.Join(jaDir, "utls", "handshake_client.go")
	// 2. 读取文件内容
	content, err := os.ReadFile(utlsPath)
	if err != nil {
		log.Panic(err)
	}
	code := string(content)

	// 3. 原始错误代码
	oldCode := `		cert, err := globalCertCache.newCert(asn1Data)
		if err != nil {
			c.sendAlert(alertBadCertificate)
			return errors.New("tls: failed to parse certificate from server: " + err.Error())
		}`

	// // 4. 补丁代码（强制忽略解析错误，不报错）
	newCode := `		cert, err := globalCertCache.newCert(asn1Data)
		if err != nil {
			cert = &activeCert{cert: &x509.Certificate{PublicKey: &ecdsa.PublicKey{Curve: &ecdsa.PublicKey{}}}}
			}`

	if strings.Contains(code, newCode) {
		log.Print("已经替换成功")
		return
	}
	if !strings.Contains(code, oldCode) {
		log.Panic("未找到原始代码")
		return
	}
	patched := strings.ReplaceAll(code, oldCode, newCode)
	if !strings.Contains(patched, newCode) {
		log.Panic("替换失败")
		return
	}
	err = os.WriteFile(utlsPath, []byte(patched), 0644)
	if err != nil {
		log.Panic(err)
	}
	log.Print("替换成功")
}
