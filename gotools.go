package gotools

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io/ioutil"
	"math"
	"math/rand"
	"strings"
	"time"

	fiber "github.com/gofiber/fiber/v2"
	http2 "github.com/kawacode/fhttp/http2"
	gostruct "github.com/kawacode/gostruct"
	tls "github.com/kawacode/utls"
)

// It takes a JA3 string and returns a tls.ClientHelloSpec
func ParseJA3(Ja3 string, Protocol string) (*tls.ClientHelloSpec, error) {
	var (
		tlsspec    tls.ClientHelloSpec
		tlsinfo    tls.ClientHelloInfo
		extensions string
	)
	for i, v := range strings.SplitN(Ja3, ",", 5) {
		switch i {
		case 0:
			_, err := fmt.Sscan(v, &tlsspec.TLSVersMax)
			if err != nil {
				return nil, err
			}
		case 1:
			tlsspec.CipherSuites = append(tlsspec.CipherSuites, tls.GREASE_PLACEHOLDER)
			for _, chiperkey := range strings.Split(v, "-") {
				var cipher uint16
				_, err := fmt.Sscan(chiperkey, &cipher)
				if err != nil {
					return nil, err
				}
				tlsspec.CipherSuites = append(tlsspec.CipherSuites, cipher)
			}
		case 2:
			extensions = v
		case 3:
			tlsinfo.SupportedCurves = append(tlsinfo.SupportedCurves, tls.GREASE_PLACEHOLDER)
			for _, curveid := range strings.Split(v, "-") {
				var curves tls.CurveID
				_, err := fmt.Sscan(curveid, &curves)
				if err != nil {
					return nil, err
				}
				tlsinfo.SupportedCurves = append(tlsinfo.SupportedCurves, curves)
			}
		case 4:
			for _, point := range strings.Split(v, "-") {
				var points uint8
				_, err := fmt.Sscan(point, &points)
				if err != nil {
					return nil, err
				}
				tlsinfo.SupportedPoints = append(tlsinfo.SupportedPoints, points)
			}
		}
	}
	tlsspec.Extensions = append(tlsspec.Extensions, &tls.UtlsGREASEExtension{})
	for _, extenionsvalue := range strings.Split(extensions, "-") {
		var tlsext tls.TLSExtension
		switch extenionsvalue {
		case "0":
			tlsext = &tls.SNIExtension{}
		case "5":
			tlsext = &tls.StatusRequestExtension{}
		case "10":
			tlsext = &tls.SupportedCurvesExtension{Curves: tlsinfo.SupportedCurves}
		case "11":
			tlsext = &tls.SupportedPointsExtension{SupportedPoints: tlsinfo.SupportedPoints}
		case "13":
			tlsext = &tls.SignatureAlgorithmsExtension{
				SupportedSignatureAlgorithms: []tls.SignatureScheme{
					1027,
					2052,
					1025,
					1283,
					2053,
					1281,
					2054,
					1537,
				},
			}
		case "16":
			if Protocol == "1" {
				tlsext = &tls.ALPNExtension{
					AlpnProtocols: []string{"http/1.1"},
				}
			} else {
				tlsext = &tls.ALPNExtension{
					AlpnProtocols: []string{"h2"},
				}
			}
		case "18":
			tlsext = &tls.SCTExtension{}
		case "21":
			tlsspec.Extensions = append(tlsspec.Extensions, &tls.UtlsGREASEExtension{})
			tlsext = &tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle}
		case "22":
			tlsext = &tls.GenericExtension{Id: 22}
		case "23":
			tlsext = &tls.UtlsExtendedMasterSecretExtension{}
		case "27":
			tlsext = &tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{tls.CertCompressionBrotli, tls.CertCompressionZlib}}
		case "28":
			tlsext = &tls.FakeRecordSizeLimitExtension{}
		case "34":
			tlsext = &tls.DelegatedCredentialsExtension{
				AlgorithmsSignature: []tls.SignatureScheme{
					1027,
					2052,
					1025,
					1283,
					2053,
					1281,
					2054,
					1537,
				},
			}
		case "35":
			tlsext = &tls.SessionTicketExtension{}
		case "43":
			tlsext = &tls.SupportedVersionsExtension{Versions: []uint16{tlsspec.TLSVersMax}}
		case "45":
			tlsext = &tls.PSKKeyExchangeModesExtension{
				Modes: []uint8{tls.PskModeDHE},
			}
		case "49":
			tlsext = &tls.GenericExtension{Id: 49}
		case "50":
			tlsext = &tls.GenericExtension{Id: 50}
		case "51":
			tlsext = &tls.KeyShareExtension{KeyShares: []tls.KeyShare{
				{Group: 29, Data: []byte{32}},
				{Group: 23, Data: []byte{65}},
			}}
		case "13172":
			tlsext = &tls.NPNExtension{}
		case "17513":
			if Protocol == "1" {
				tlsext = &tls.ALPSExtension{SupportedProtocols: []string{"http/1.1"}}
			} else {
				tlsext = &tls.ALPSExtension{SupportedProtocols: []string{"h2"}}
			}
		case "30032":
			tlsext = &tls.GenericExtension{Id: 0x7550, Data: []byte{0}}
		case "65281":
			tlsext = &tls.RenegotiationInfoExtension{
				Renegotiation: tls.RenegotiateOnceAsClient,
			}
		case "41":
			tlsext = &tls.PreSharedKeyExtension{}
		case "42":
			tlsext = &tls.GenericExtension{Id: tls.ExtensionEarlyData}
		case "44":
			tlsext = &tls.CookieExtension{}
		default:
			var id uint16
			_, err := fmt.Sscan(extenionsvalue, &id)
			if err != nil {
				return nil, err
			}
			tlsext = &tls.GenericExtension{Id: id}
		}
		tlsspec.Extensions = append(tlsspec.Extensions, tlsext)
	}
	tlsspec.TLSVersMin = tls.VersionTLS10
	return &tlsspec, nil
}

// `GetHelloClient` is a function that takes a string as an argument and returns a pointer to a
func GetHelloClient(client string) *tls.ClientHelloID {
	switch strings.ToUpper(client) {
	case strings.ToUpper("HelloCustom"):
		return &tls.HelloCustom
	case strings.ToUpper("HelloChrome_58"):
		return &tls.HelloChrome_58
	case strings.ToUpper("HelloChrome_62"):
		return &tls.HelloChrome_62
	case strings.ToUpper("HelloChrome_70"):
		return &tls.HelloChrome_70
	case strings.ToUpper("HelloChrome_72"):
		return &tls.HelloChrome_72
	case strings.ToUpper("HelloChrome_83"):
		return &tls.HelloChrome_83
	case strings.ToUpper("HelloChrome_87"):
		return &tls.HelloChrome_87
	case strings.ToUpper("HelloChrome_96"):
		return &tls.HelloChrome_96
	case strings.ToUpper("HelloChrome_100"):
		return &tls.HelloChrome_100
	case strings.ToUpper("HelloChrome_103"):
		return &tls.HelloChrome_103
	case strings.ToUpper("HelloChrome_104"):
		return &tls.HelloChrome_104
	case strings.ToUpper("HelloChrome_105"):
		return &tls.HelloChrome_105
	case strings.ToUpper("HelloChrome_106"):
		return &tls.HelloChrome_106
	case strings.ToUpper("HelloChrome_107"):
		return &tls.HelloChrome_107
	case strings.ToUpper("HelloChrome_Auto"):
		return &tls.HelloChrome_Auto
	case strings.ToUpper("HelloFirefox_55"):
		return &tls.HelloFirefox_55
	case strings.ToUpper("HelloFirefox_56"):
		return &tls.HelloFirefox_56
	case strings.ToUpper("HelloFirefox_63"):
		return &tls.HelloFirefox_63
	case strings.ToUpper("HelloFirefox_65"):
		return &tls.HelloFirefox_65
	case strings.ToUpper("HelloFirefox_102"):
		return &tls.HelloFirefox_102
	case strings.ToUpper("HelloFirefox_104"):
		return &tls.HelloFirefox_104
	case strings.ToUpper("HelloFirefox_105"):
		return &tls.HelloFirefox_105
	case strings.ToUpper("HelloFirefox_Auto"):
		return &tls.HelloFirefox_Auto
	case strings.ToUpper("HelloAndroid_11_OkHttp"):
		return &tls.HelloAndroid_11_OkHttp
	case strings.ToUpper("HelloIOS_11_1"):
		return &tls.HelloIOS_11_1
	case strings.ToUpper("HelloIOS_12_1"):
		return &tls.HelloIOS_12_1
	case strings.ToUpper("HelloIOS_13"):
		return &tls.HelloIOS_13
	case strings.ToUpper("HelloIOS_14"):
		return &tls.HelloIOS_14
	case strings.ToUpper("HelloIOS_15_5"):
		return &tls.HelloIOS_15_5
	case strings.ToUpper("HelloIOS_15_6"):
		return &tls.HelloIOS_15_6
	case strings.ToUpper("HelloIOS_16_0"):
		return &tls.HelloIOS_16_0
	case strings.ToUpper("HelloIOS_Auto"):
		return &tls.HelloIOS_Auto
	case strings.ToUpper("HelloSafari_16_0"):
		return &tls.HelloSafari_16_0
	case strings.ToUpper("HelloSafari_15_6_1"):
		return &tls.HelloSafari_15_6_1
	case strings.ToUpper("HelloSafari_Auto"):
		return &tls.HelloIPad_15_6
	case strings.ToUpper("HelloIPad_15_6"):
		return &tls.HelloIPad_Auto
	case strings.ToUpper("HelloIPad_Auto"):
		return &tls.HelloSafari_Auto
	case strings.ToUpper("HelloGolang"):
		return &tls.HelloGolang
	case strings.ToUpper("HelloOpera_89"):
		return &tls.HelloOpera_89
	case strings.ToUpper("HelloOpera_90"):
		return &tls.HelloOpera_90
	case strings.ToUpper("HelloOpera_Auto"):
		return &tls.HelloOpera_Auto
	case strings.ToUpper("HelloRandomized"):
		return &tls.HelloRandomized
	case strings.ToUpper("HelloRandomizedALPN"):
		return &tls.HelloRandomizedALPN
	case strings.ToUpper("HelloRandomizedNoALPN"):
		return &tls.HelloRandomizedNoALPN
	default:
		return &tls.HelloChrome_Auto
	}
}

// Convert a map of string slices to a map of strings.
func MapStringSliceToMapString(headers map[string][]string) map[string]string {
	var result = make(map[string]string)
	for key, value := range headers {
		for _, value := range value {
			result[key] = value
		}
	}
	return result
}

// It takes a map of strings and returns a map of strings with removed kawacode headers
func RemoveKawaCodeHeaders(headers map[string]string, bot *gostruct.BotData) map[string]string {
	returnheaders := make(map[string]string)
	for k, v := range headers {
		if strings.Contains(strings.ToLower(k), "host") {
			returnheaders[k] = strings.Split(bot.HttpRequest.Request.URL, "/")[2]
		} else if !strings.Contains(strings.ToLower(k), "x-kc-") {
			returnheaders[k] = v
		}
	}
	return returnheaders
}

// > Converts a map of strings to a map of string slices
func MapStringToMapStringSlice(MapString map[string]string, bot *gostruct.BotData) map[string][]string {
	var result = make(map[string][]string)
	for key, value := range MapString {
		if strings.Contains(key, "Content-Length") {
		} else {
			result[key] = []string{value}
		}
	}
	if len(bot.HttpRequest.Request.HeaderOrderKey) > 1 {
		var HeaderOrderKey []string
		for _, v := range bot.HttpRequest.Request.HeaderOrderKey {
			HeaderOrderKey = append(HeaderOrderKey, strings.ReplaceAll(v, " ", ""))
		}
		result["Header-Order:"] = HeaderOrderKey
	}
	if len(bot.HttpRequest.Request.HTTP2TRANSPORT.ClientProfile.PseudoHeaderOrder) > 1 {
		var PHeaderOrderKey []string
		for _, v := range bot.HttpRequest.Request.HTTP2TRANSPORT.ClientProfile.PseudoHeaderOrder {
			PHeaderOrderKey = append(PHeaderOrderKey, strings.ReplaceAll(v, " ", ""))
		}
		result["PHeader-Order:"] = PHeaderOrderKey
	} else {
		result["PHeader-Order:"] = []string{
			":method",
			":authority",
			":scheme",
			":path",
		}
	}
	return result
}

// It takes two integers, min and max, and returns a random integer between min and max
func RandomInt(min int, max int) int {
	rand.Seed(time.Now().UnixNano())
	return (min + rand.Intn(max-min))
}

// It takes a string, converts it to a byte array, creates a new gzip reader, reads the gzip reader,
// and returns the result as a string
func DecompressGzip(Gzip string) (string, error) {
	res, err := gzip.NewReader(bytes.NewReader([]byte(Gzip)))
	if err != nil {
		return Gzip, nil
	}
	defer res.Close()
	read, err := ioutil.ReadAll(res)
	if err != nil {
		return "", err
	}
	return string(read), nil
}

// It returns true if the string is made up of digits, false otherwise
func IsInt(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// It takes a Go request and sets the Fiber request to match it
func SetGoRequestToFiber(request *fiber.Ctx, bot *gostruct.BotData) {
	request.SendStatus(bot.HttpRequest.Response.StatusCode)
	request.SendString(bot.HttpRequest.Response.Source)
	for k, v := range bot.HttpRequest.Response.Cookies {
		cookie := new(fiber.Cookie)
		cookie.Name = k
		cookie.Value = v
		cookie.Expires = time.Now().Add(time.Duration(24 * time.Hour))
		request.Cookie(cookie)
	}
	for k, v := range bot.HttpRequest.Response.Headers {
		if !strings.Contains(strings.ToLower(strings.ReplaceAll(k, " ", "")), "set-cookie") {
			request.Set(k, v)
		}
	}
}
func GetHttp2SettingsfromClient(bot *gostruct.BotData) {
	type ClientProfile struct {
		Settings          map[http2.SettingID]uint32
		SettingsOrder     []http2.SettingID
		PseudoHeaderOrder []string
		ConnectionFlow    uint32
		Priorities        []http2.Priority
	}
	var Chrome_106 = ClientProfile{
		Settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:      65536,
			http2.SettingEnablePush:           0,
			http2.SettingMaxConcurrentStreams: 1000,
			http2.SettingInitialWindowSize:    6291456,
			http2.SettingMaxHeaderListSize:    262144,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingEnablePush,
			http2.SettingMaxConcurrentStreams,
			http2.SettingInitialWindowSize,
			http2.SettingMaxHeaderListSize,
		},
		PseudoHeaderOrder: []string{
			":method",
			":authority",
			":scheme",
			":path",
		},
		ConnectionFlow: 15663105,
	}

	var Chrome_105 = ClientProfile{
		Settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:      65536,
			http2.SettingMaxConcurrentStreams: 1000,
			http2.SettingInitialWindowSize:    6291456,
			http2.SettingMaxHeaderListSize:    262144,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingMaxConcurrentStreams,
			http2.SettingInitialWindowSize,
			http2.SettingMaxHeaderListSize,
		},
		PseudoHeaderOrder: []string{
			":method",
			":authority",
			":scheme",
			":path",
		},
		ConnectionFlow: 15663105,
	}

	var Chrome_104 = ClientProfile{
		Settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:      65536,
			http2.SettingMaxConcurrentStreams: 1000,
			http2.SettingInitialWindowSize:    6291456,
			http2.SettingMaxHeaderListSize:    262144,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingMaxConcurrentStreams,
			http2.SettingInitialWindowSize,
			http2.SettingMaxHeaderListSize,
		},
		PseudoHeaderOrder: []string{
			":method",
			":authority",
			":scheme",
			":path",
		},
		ConnectionFlow: 15663105,
	}

	var Chrome_103 = ClientProfile{
		Settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:      65536,
			http2.SettingMaxConcurrentStreams: 1000,
			http2.SettingInitialWindowSize:    6291456,
			http2.SettingMaxHeaderListSize:    262144,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingMaxConcurrentStreams,
			http2.SettingInitialWindowSize,
			http2.SettingMaxHeaderListSize,
		},
		PseudoHeaderOrder: []string{
			":method",
			":authority",
			":scheme",
			":path",
		},
		ConnectionFlow: 15663105,
	}

	var Safari_15_6_1 = ClientProfile{
		Settings: map[http2.SettingID]uint32{
			http2.SettingInitialWindowSize:    4194304,
			http2.SettingMaxConcurrentStreams: 100,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingInitialWindowSize,
			http2.SettingMaxConcurrentStreams,
		},
		PseudoHeaderOrder: []string{
			":method",
			":scheme",
			":path",
			":authority",
		},
		ConnectionFlow: 10485760,
	}

	var Safari_16_0 = ClientProfile{
		Settings: map[http2.SettingID]uint32{
			http2.SettingInitialWindowSize:    4194304,
			http2.SettingMaxConcurrentStreams: 100,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingInitialWindowSize,
			http2.SettingMaxConcurrentStreams,
		},
		PseudoHeaderOrder: []string{
			":method",
			":scheme",
			":path",
			":authority",
		},
		ConnectionFlow: 10485760,
	}

	var Safari_Ipad_15_6 = ClientProfile{
		Settings: map[http2.SettingID]uint32{
			http2.SettingInitialWindowSize:    2097152,
			http2.SettingMaxConcurrentStreams: 100,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingInitialWindowSize,
			http2.SettingMaxConcurrentStreams,
		},
		PseudoHeaderOrder: []string{
			":method",
			":scheme",
			":path",
			":authority",
		},
		ConnectionFlow: 10485760,
	}

	var Safari_IOS_16_0 = ClientProfile{
		Settings: map[http2.SettingID]uint32{
			http2.SettingInitialWindowSize:    2097152,
			http2.SettingMaxConcurrentStreams: 100,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingInitialWindowSize,
			http2.SettingMaxConcurrentStreams,
		},
		PseudoHeaderOrder: []string{
			":method",
			":scheme",
			":path",
			":authority",
		},
		ConnectionFlow: 10485760,
	}

	var Safari_IOS_15_5 = ClientProfile{
		Settings: map[http2.SettingID]uint32{
			http2.SettingInitialWindowSize:    2097152,
			http2.SettingMaxConcurrentStreams: 100,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingInitialWindowSize,
			http2.SettingMaxConcurrentStreams,
		},
		PseudoHeaderOrder: []string{
			":method",
			":scheme",
			":path",
			":authority",
		},
		ConnectionFlow: 10485760,
	}

	var Safari_IOS_15_6 = ClientProfile{
		Settings: map[http2.SettingID]uint32{
			http2.SettingInitialWindowSize:    2097152,
			http2.SettingMaxConcurrentStreams: 100,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingInitialWindowSize,
			http2.SettingMaxConcurrentStreams,
		},
		PseudoHeaderOrder: []string{
			":method",
			":scheme",
			":path",
			":authority",
		},
		ConnectionFlow: 10485760,
	}

	var Firefox_106 = ClientProfile{
		Settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:   65536,
			http2.SettingInitialWindowSize: 131072,
			http2.SettingMaxFrameSize:      16384,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingInitialWindowSize,
			http2.SettingMaxFrameSize,
		},
		PseudoHeaderOrder: []string{
			":method",
			":path",
			":authority",
			":scheme",
		},
		ConnectionFlow: 12517377,
		Priorities: []http2.Priority{
			{StreamID: 3, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    200,
			}},
			{StreamID: 5, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    100,
			}},
			{StreamID: 7, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 9, PriorityParam: http2.PriorityParam{
				StreamDep: 7,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 11, PriorityParam: http2.PriorityParam{
				StreamDep: 3,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 13, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    240,
			}},
		},
	}

	var Firefox_105 = ClientProfile{
		Settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:   65536,
			http2.SettingInitialWindowSize: 131072,
			http2.SettingMaxFrameSize:      16384,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingInitialWindowSize,
			http2.SettingMaxFrameSize,
		},
		PseudoHeaderOrder: []string{
			":method",
			":path",
			":authority",
			":scheme",
		},
		ConnectionFlow: 12517377,
		Priorities: []http2.Priority{
			{StreamID: 3, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    200,
			}},
			{StreamID: 5, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    100,
			}},
			{StreamID: 7, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 9, PriorityParam: http2.PriorityParam{
				StreamDep: 7,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 11, PriorityParam: http2.PriorityParam{
				StreamDep: 3,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 13, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    240,
			}},
		},
	}

	var Firefox_104 = ClientProfile{
		Settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:   65536,
			http2.SettingInitialWindowSize: 131072,
			http2.SettingMaxFrameSize:      16384,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingInitialWindowSize,
			http2.SettingMaxFrameSize,
		},
		PseudoHeaderOrder: []string{
			":method",
			":path",
			":authority",
			":scheme",
		},
		ConnectionFlow: 12517377,
		Priorities: []http2.Priority{
			{StreamID: 3, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    200,
			}},
			{StreamID: 5, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    100,
			}},
			{StreamID: 7, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 9, PriorityParam: http2.PriorityParam{
				StreamDep: 7,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 11, PriorityParam: http2.PriorityParam{
				StreamDep: 3,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 13, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    240,
			}},
		},
	}

	var Firefox_102 = ClientProfile{
		Settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:   65536,
			http2.SettingInitialWindowSize: 131072,
			http2.SettingMaxFrameSize:      16384,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingInitialWindowSize,
			http2.SettingMaxFrameSize,
		},
		PseudoHeaderOrder: []string{
			":method",
			":path",
			":authority",
			":scheme",
		},
		ConnectionFlow: 12517377,
		Priorities: []http2.Priority{
			{StreamID: 3, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    200,
			}},
			{StreamID: 5, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    100,
			}},
			{StreamID: 7, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 9, PriorityParam: http2.PriorityParam{
				StreamDep: 7,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 11, PriorityParam: http2.PriorityParam{
				StreamDep: 3,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 13, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    240,
			}},
		},
	}

	var Opera_90 = ClientProfile{
		Settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:      65536,
			http2.SettingMaxConcurrentStreams: 1000,
			http2.SettingInitialWindowSize:    6291456,
			http2.SettingMaxHeaderListSize:    262144,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingMaxConcurrentStreams,
			http2.SettingInitialWindowSize,
			http2.SettingMaxHeaderListSize,
		},
		PseudoHeaderOrder: []string{
			":method",
			":authority",
			":scheme",
			":path",
		},
		ConnectionFlow: 15663105,
	}

	var Opera_91 = ClientProfile{
		Settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:      65536,
			http2.SettingMaxConcurrentStreams: 1000,
			http2.SettingInitialWindowSize:    6291456,
			http2.SettingMaxHeaderListSize:    262144,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingMaxConcurrentStreams,
			http2.SettingInitialWindowSize,
			http2.SettingMaxHeaderListSize,
		},
		PseudoHeaderOrder: []string{
			":method",
			":authority",
			":scheme",
			":path",
		},
		ConnectionFlow: 15663105,
	}

	var Opera_89 = ClientProfile{
		Settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:      65536,
			http2.SettingMaxConcurrentStreams: 1000,
			http2.SettingInitialWindowSize:    6291456,
			http2.SettingMaxHeaderListSize:    262144,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingMaxConcurrentStreams,
			http2.SettingInitialWindowSize,
			http2.SettingMaxHeaderListSize,
		},
		PseudoHeaderOrder: []string{
			":method",
			":authority",
			":scheme",
			":path",
		},
		ConnectionFlow: 15663105,
	}
	var ZalandoAndroidMobile = ClientProfile{
		Settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:      4096,
			http2.SettingMaxConcurrentStreams: math.MaxUint32,
			http2.SettingInitialWindowSize:    16777216,
			http2.SettingMaxFrameSize:         16384,
			http2.SettingMaxHeaderListSize:    math.MaxUint32,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingMaxConcurrentStreams,
			http2.SettingInitialWindowSize,
			http2.SettingMaxFrameSize,
			http2.SettingMaxHeaderListSize,
		},
		PseudoHeaderOrder: []string{
			":method",
			":path",
			":authority",
			":scheme",
		},
		ConnectionFlow: 15663105,
	}

	var ZalandoIosMobile = ClientProfile{
		Settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:      4096,
			http2.SettingMaxConcurrentStreams: 100,
			http2.SettingInitialWindowSize:    2097152,
			http2.SettingMaxFrameSize:         16384,
			http2.SettingMaxHeaderListSize:    math.MaxUint32,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingMaxConcurrentStreams,
			http2.SettingInitialWindowSize,
			http2.SettingMaxFrameSize,
			http2.SettingMaxHeaderListSize,
		},
		PseudoHeaderOrder: []string{
			":method",
			":path",
			":authority",
			":scheme",
		},
		ConnectionFlow: 15663105,
	}

	var NikeIosMobile = ClientProfile{
		Settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:      4096,
			http2.SettingMaxConcurrentStreams: 100,
			http2.SettingInitialWindowSize:    2097152,
			http2.SettingMaxFrameSize:         16384,
			http2.SettingMaxHeaderListSize:    math.MaxUint32,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingMaxConcurrentStreams,
			http2.SettingInitialWindowSize,
			http2.SettingMaxFrameSize,
			http2.SettingMaxHeaderListSize,
		},
		PseudoHeaderOrder: []string{
			":method",
			":scheme",
			":path",
			":authority",
		},
		ConnectionFlow: 15663105,
	}

	var NikeAndroidMobile = ClientProfile{
		Settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:      4096,
			http2.SettingMaxConcurrentStreams: math.MaxUint32,
			http2.SettingInitialWindowSize:    16777216,
			http2.SettingMaxFrameSize:         16384,
			http2.SettingMaxHeaderListSize:    math.MaxUint32,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingMaxConcurrentStreams,
			http2.SettingInitialWindowSize,
			http2.SettingMaxFrameSize,
			http2.SettingMaxHeaderListSize,
		},
		PseudoHeaderOrder: []string{
			":method",
			":path",
			":authority",
			":scheme",
		},
		ConnectionFlow: 15663105,
	}

	var CloudflareCustom = ClientProfile{
		//actually the h2 Settings are not relevant, because this client does only support http1
		Settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:      4096,
			http2.SettingMaxConcurrentStreams: math.MaxUint32,
			http2.SettingInitialWindowSize:    16777216,
			http2.SettingMaxFrameSize:         16384,
			http2.SettingMaxHeaderListSize:    math.MaxUint32,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingMaxConcurrentStreams,
			http2.SettingInitialWindowSize,
			http2.SettingMaxFrameSize,
			http2.SettingMaxHeaderListSize,
		},
		PseudoHeaderOrder: []string{
			":method",
			":path",
			":authority",
			":scheme",
		},
		ConnectionFlow: 15663105,
	}
	var TLSClients = map[string]ClientProfile{
		tls.HelloChrome_103.Str():    Chrome_103,
		tls.HelloChrome_104.Str():    Chrome_104,
		tls.HelloChrome_105.Str():    Chrome_105,
		tls.HelloChrome_106.Str():    Chrome_106,
		tls.HelloSafari_15_6_1.Str(): Safari_15_6_1,
		tls.HelloSafari_16_0.Str():   Safari_16_0,
		tls.HelloIPad_15_6.Str():     Safari_Ipad_15_6,
		tls.HelloIOS_15_5.Str():      Safari_IOS_15_5,
		tls.HelloIOS_15_6.Str():      Safari_IOS_15_6,
		tls.HelloIOS_16_0.Str():      Safari_IOS_16_0,
		tls.HelloFirefox_102.Str():   Firefox_102,
		tls.HelloFirefox_104.Str():   Firefox_104,
		tls.HelloFirefox_105.Str():   Firefox_105,
		tls.HelloFirefox_106.Str():   Firefox_106,
		tls.HelloOpera_89.Str():      Opera_89,
		tls.HelloOpera_90.Str():      Opera_90,
		tls.HelloOpera_91.Str():      Opera_91,
		"zalando_android_mobile":     ZalandoAndroidMobile,
		"zalando_ios_mobile":         ZalandoIosMobile,
		"nike_ios_mobile":            NikeIosMobile,
		"nike_android_mobile":        NikeAndroidMobile,
		"cloudflare_custom":          CloudflareCustom,
	}

	if profile, exist := TLSClients[bot.HttpRequest.Request.Client.Str()]; exist {
		bot.HttpRequest.Request.HTTP2TRANSPORT.ClientProfile = profile
	} else {
		bot.HttpRequest.Request.HTTP2TRANSPORT.ClientProfile = Chrome_106
	}
}
