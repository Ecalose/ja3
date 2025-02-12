package ja3

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"sync"

	"github.com/gospider007/http3"
	"github.com/gospider007/kinds"
	"github.com/gospider007/re"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/exp/slices"
)

type specErr struct {
	KeyShareExtension *kinds.Set[uint16]
}
type Client struct {
	specErrData sync.Map
}

func NewClient() *Client {
	return &Client{}
}
func (obj *Client) setSpecErrWithKeyShareExtension(key string, value uint16) (change bool) {
	errData, ok := obj.specErrData.Load(key)
	if ok {
		specErr := errData.(*specErr)
		if !specErr.KeyShareExtension.Has(value) {
			change = true
			specErr.KeyShareExtension.Add(value)
		}
	} else {
		change = true
		obj.specErrData.Store(key, &specErr{KeyShareExtension: kinds.NewSet(value)})
	}
	return
}
func (obj *Client) setSpecErrWithError(key string, err error) (change bool) {
	keyShareExtensionRs := re.Search(`unsupported Curve in KeyShareExtension: CurveID\((\d+)\)`, err.Error())
	if keyShareExtensionRs != nil {
		i, err := strconv.Atoi(keyShareExtensionRs.Group(1))
		if err == nil {
			if obj.setSpecErrWithKeyShareExtension(key, uint16(i)) {
				change = true
			}
		}
	}
	return
}
func (obj *Client) changeSpec(key string, spec utls.ClientHelloSpec) (change bool) {
	errData, ok := obj.specErrData.Load(key)
	if !ok {
		return
	}
	specErr := errData.(*specErr)
	for _, ext := range spec.Extensions {
		switch extData := ext.(type) {
		case *utls.KeyShareExtension:
			if specErr.KeyShareExtension.Len() > 0 {
				keyShares := []utls.KeyShare{}
				for _, keyShare := range extData.KeyShares {
					if !specErr.KeyShareExtension.Has(uint16(keyShare.Group)) {
						change = true
						keyShares = append(keyShares, keyShare)
					}
				}
				extData.KeyShares = keyShares
			}
		case *utls.SupportedCurvesExtension:
			if specErr.KeyShareExtension.Len() > 0 {
				keyShares := []utls.CurveID{}
				for _, keyShare := range extData.Curves {
					if !specErr.KeyShareExtension.Has(uint16(keyShare)) {
						change = true
						keyShares = append(keyShares, keyShare)
					}
				}
				extData.Curves = keyShares
			}
		}
	}
	return
}

func createSpecWithSpec(utlsSpec utls.ClientHelloSpec, h2 bool, h3 bool) (utls.ClientHelloSpec, error) {
	if h3 {
		for _, Extension := range utlsSpec.Extensions {
			alpns, ok := Extension.(*utls.ALPNExtension)
			if ok {
				alpns.AlpnProtocols = []string{http3.NextProtoH3}
				break
			}
		}
	} else if !h2 {
		for _, Extension := range utlsSpec.Extensions {
			alpns, ok := Extension.(*utls.ALPNExtension)
			if ok {
				if i := slices.Index(alpns.AlpnProtocols, "h2"); i != -1 {
					alpns.AlpnProtocols = slices.Delete(alpns.AlpnProtocols, i, i+1)
				}
				if !slices.Contains(alpns.AlpnProtocols, "http/1.1") {
					alpns.AlpnProtocols = append([]string{"http/1.1"}, alpns.AlpnProtocols...)
				}
				break
			}
		}
	}
	return utlsSpec, nil
}

func (obj *Client) Client(ctx context.Context, conn net.Conn, ja3Spec utls.ClientHelloSpec, h2 bool, utlsConfig *utls.Config, serverName string) (utlsConn *utls.UConn, err error) {
	utlsSpec, err := createSpecWithSpec(ja3Spec, h2, false)
	if err != nil {
		return nil, err
	}
	utlsConfig.ServerName = serverName
	obj.changeSpec(serverName, utlsSpec)
	utlsConn = utls.UClient(conn, utlsConfig, utls.HelloCustom)
	uspec := utls.ClientHelloSpec(utlsSpec)
	for {
		err = utlsConn.ApplyPreset(&uspec)
		if err == nil {
			break
		}
		if !obj.setSpecErrWithError(serverName, err) {
			return nil, err
		}
		if !obj.changeSpec(serverName, utlsSpec) {
			return nil, err
		}
	}
	err = utlsConn.HandshakeContext(ctx)
	return utlsConn, err
}

type Http2SettingID uint16

const (
	Http2SettingHeaderTableSize      Http2SettingID = 0x1
	Http2SettingEnablePush           Http2SettingID = 0x2
	Http2SettingMaxConcurrentStreams Http2SettingID = 0x3
	Http2SettingInitialWindowSize    Http2SettingID = 0x4
	Http2SettingMaxFrameSize         Http2SettingID = 0x5
	Http2SettingMaxHeaderListSize    Http2SettingID = 0x6
)

type Setting struct {
	// ID is which setting is being set.
	// See https://httpwg.org/specs/rfc7540.html#SettingFormat
	Id Http2SettingID
	// Val is the value.
	Val uint32
}
type Priority struct {
	// StreamDep is a 31-bit stream identifier for the
	// stream that this stream depends on. Zero means no
	// dependency.
	StreamDep uint32

	// Exclusive is whether the dependency is exclusive.
	Exclusive bool

	// Weight is the stream's zero-indexed weight. It should be
	// set together with StreamDep, or neither should be set. Per
	// the spec, "Add one to the value to obtain a weight between
	// 1 and 256."
	Weight uint8
}

// have value
func (obj Priority) IsSet() bool {
	if obj.StreamDep != 0 || obj.Exclusive || obj.Weight != 0 {
		return true
	}
	return false
}

func DefaultSpec() utls.ClientHelloSpec {
	spec, _ := CreateSpecWithClientHello(utls.HelloChrome_Auto)
	return spec
}

var defaultOrderHeadersH2 = []string{
	":method",
	":authority",
	":scheme",
	":path",
}
var defaultOrderHeaders = []string{
	":method",
	":authority",
	":scheme",
	":path",
	"Host",
	"Connection",
	"Content-Length",
	"pragma",
	"cache-control",
	"sec-ch-ua",
	"sec-ch-ua-mobile",
	"sec-ch-ua-platform",
	"upgrade-insecure-requests",
	"accept",
	"user-agent",
	"origin",
	"Referer",
	"sec-fetch-site",
	"sec-fetch-mode",
	"sec-fetch-user",
	"sec-fetch-dest",
	"accept-encoding",
	"accept-language",
	"Cookie",
}

func DefaultOrderHeaders() []string {
	headers := make([]string, len(defaultOrderHeaders))
	for i, key := range defaultOrderHeaders {
		headers[i] = textproto.CanonicalMIMEHeaderKey(key)
	}
	return headers
}
func DefaultOrderHeadersWithH2() []string {
	headers := make([]string, len(defaultOrderHeadersH2))
	copy(headers, defaultOrderHeaders)
	return headers
}
func DefaultH2Spec() H2Spec {
	var h2Spec H2Spec
	h2Spec.InitialSetting = []Setting{
		{Id: 1, Val: 65536},
		{Id: 2, Val: 0},
		{Id: 3, Val: 1000},
		{Id: 4, Val: 6291456},
		{Id: 6, Val: 262144},
	}
	h2Spec.Priority = Priority{
		Exclusive: true,
		StreamDep: 0,
		Weight:    255,
	}
	h2Spec.OrderHeaders = DefaultOrderHeaders()
	h2Spec.ConnFlow = 15663105
	return h2Spec
}

type H2Spec struct {
	InitialSetting []Setting
	ConnFlow       uint32   //WINDOW_UPDATE:15663105
	OrderHeaders   []string //example：[]string{":method",":authority",":scheme",":path"}
	Priority       Priority
}

// have value
func (obj H2Spec) IsSet() bool {
	if obj.InitialSetting != nil || obj.ConnFlow != 0 || obj.OrderHeaders != nil || obj.Priority.IsSet() {
		return true
	}
	return false
}

func (obj H2Spec) Fp() string {
	settings := []string{}
	for _, setting := range obj.InitialSetting {
		settings = append(settings, fmt.Sprintf("%d:%d", setting.Id, setting.Val))
	}
	heads := []string{}
	for _, head := range obj.OrderHeaders {
		head = strings.ToLower(head)
		switch head {
		case ":method":
			heads = append(heads, "m")
		case ":authority":
			heads = append(heads, "a")
		case ":scheme":
			heads = append(heads, "s")
		case ":path":
			heads = append(heads, "p")
		}
	}
	return strings.Join([]string{
		strings.Join(settings, ","),
		fmt.Sprint(obj.ConnFlow),
		"0",
		strings.Join(heads, ","),
	}, "|")
}

// example："1:65536,2:0,4:6291456,6:262144|15663105|0|m,a,s,p"
func CreateH2SpecWithStr(h2ja3SpecStr string) (h2ja3Spec H2Spec, err error) {
	tokens := strings.Split(h2ja3SpecStr, "|")
	if len(tokens) != 4 {
		err = errors.New("h2 spec format error")
		return
	}
	h2ja3Spec.InitialSetting = []Setting{}
	for _, setting := range strings.Split(tokens[0], ",") {
		tts := strings.Split(setting, ":")
		if len(tts) != 2 {
			err = errors.New("h2 setting error")
			return
		}
		var ttKey, ttVal int
		if ttKey, err = strconv.Atoi(tts[0]); err != nil {
			return
		}
		if ttVal, err = strconv.Atoi(tts[1]); err != nil {
			return
		}
		h2ja3Spec.InitialSetting = append(h2ja3Spec.InitialSetting, Setting{
			Id:  Http2SettingID(ttKey),
			Val: uint32(ttVal),
		})
	}
	var connFlow int
	if connFlow, err = strconv.Atoi(tokens[1]); err != nil {
		return
	}
	h2ja3Spec.ConnFlow = uint32(connFlow)
	h2ja3Spec.OrderHeaders = []string{}
	for _, hkey := range strings.Split(tokens[3], ",") {
		switch hkey {
		case "m":
			h2ja3Spec.OrderHeaders = append(h2ja3Spec.OrderHeaders, ":method")
		case "a":
			h2ja3Spec.OrderHeaders = append(h2ja3Spec.OrderHeaders, ":authority")
		case "s":
			h2ja3Spec.OrderHeaders = append(h2ja3Spec.OrderHeaders, ":scheme")
		case "p":
			h2ja3Spec.OrderHeaders = append(h2ja3Spec.OrderHeaders, ":path")
		}
	}
	return
}

func CreateSpecWithClientHello(clienthello any) (clientHelloSpec utls.ClientHelloSpec, err error) {
	var clientHelloInfo ClientHello
	switch value := clienthello.(type) {
	case []byte:
		clientHelloInfo, err = decodeClientHello(value)
		if err != nil {
			return clientHelloSpec, err
		}
	case utls.ClientHelloID:
		return utls.UTLSIdToSpec(value)
	case string:
		v, err := hex.DecodeString(value)
		if err != nil {
			return clientHelloSpec, err
		}
		clientHelloInfo, err = decodeClientHello(v)
		if err != nil {
			return clientHelloSpec, err
		}
	default:
		return clientHelloSpec, errors.New("clienthello type error")
	}
	clientHelloSpec.CipherSuites = clientHelloInfo.CipherSuites
	clientHelloSpec.CompressionMethods = clientHelloInfo.CompressionMethods
	clientHelloSpec.Extensions = make([]utls.TLSExtension, len(clientHelloInfo.Extensions))
	for i, ext := range clientHelloInfo.Extensions {
		clientHelloSpec.Extensions[i] = ext.utlsExt()
	}
	clientHelloSpec.GetSessionID = sha256.Sum256
	return clientHelloSpec, nil
}
