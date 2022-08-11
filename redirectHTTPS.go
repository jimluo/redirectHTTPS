package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"strings"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/perf"
)

// 120 = 51 + 65 + 4
const (
	SizeRedirectHead = 120
	SizeRedirectUrl  = 65
)

type (
	Event struct {
		Saddr uint32
		Daddr uint32
		// Source  uint16
		// Dest    uint16
		Ttl     uint8
		Flags   uint8
		DbgType uint8
		DbgInfo uint32
	}

	redirectHTTPS struct {
		iface  *net.Interface
		bpf    redirectHTTPSObjects
		reader *perf.Reader

		timerInterval time.Duration
		timerMetrics  *time.Timer

		redirectUrl string
	}

	KernelConfig struct {
		redirectUrlLinux [SizeRedirectHead]byte
		ipHost           uint32
		macHost          [6]byte
	}
)

func ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	// binary.BigEndian.PutUint32(ip, nn)
	binary.LittleEndian.PutUint32(ip, nn)
	return ip
}

func InetNtoA(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
}

func NewredirectHTTPS(cfg *Config) *redirectHTTPS {
	bpf := redirectHTTPSObjects{}
	if err := loadredirectHTTPSObjects(&bpf, nil); err != nil {
		panic("loadredirectHTTPSObjects() " + err.Error())
	}

	fd := bpf.redirectHTTPSPrograms.XdpredirectHTTPSProg.FD()
	iface := LoadProg(fd, cfg.Ifname)

	reader, err := perf.NewReader(bpf.redirectHTTPSMaps.PKT_INFO_EVENTS_MAP, os.Getpagesize())
	if err != nil {
		panic("Creating perf event reader: " + err.Error())
	}

	redirectHTTPS := redirectHTTPS{
		iface:         iface,
		bpf:           bpf,
		reader:        reader,
		timerInterval: cfg.MetricsInterval,

		timerMetrics: time.NewTimer(cfg.MetricsInterval),

		redirectUrl: cfg.RedirectUrlLinux,
	}
	return &redirectHTTPS
}

func (n *redirectHTTPS) getLocalIP() (uint32, error) {
	addrs, err := n.iface.Addrs()
	if err != nil {
		return 0, err
	}
	for _, address := range addrs {
		ipnet, ok := address.(*net.IPNet)
		if ok && !ipnet.IP.IsLoopback() {
			ipv4 := ipnet.IP.To4() //[]byte
			if ipv4 != nil {
				log.Println("getLocalIP:", ipv4, ipnet.IP)
				return binary.BigEndian.Uint32(ipv4), nil
			}
		}
	}
	return 0, errors.New("Not found address")

}
func (n *redirectHTTPS) SetKernelConfig() {
	kcfg := KernelConfig{}
	copy(kcfg.macHost[:], n.iface.HardwareAddr[:6])

	// 120 = 51 + 65 + 4
	if len(n.redirectUrl) > SizeRedirectUrl {
		n.redirectUrl = n.redirectUrl[0:SizeRedirectUrl]
	}
	httpHead := "HTTP/1.1 302 Found\r\nContent-Length: 0\r\nLocation: "
	urlOrigin := httpHead + n.redirectUrl + "\r\n\r\n" + "\r\n\r\n"
	url := urlOrigin + strings.Repeat("\r\n\r\n", 60)
	url = url[0:SizeRedirectHead]
	copy(kcfg.redirectUrlLinux[:], []byte(url))
	l := len(urlOrigin) % 4 // must 4 bytes aligned
	kcfg.redirectUrlLinux[SizeRedirectHead-1] = byte(len(urlOrigin) - l)
	log.Println(len(urlOrigin), l, len(urlOrigin)-l)
	// log.Println("SetKernelConfig redirect head", len(url), url)

	var err error
	kcfg.ipHost, err = n.getLocalIP()
	if err != nil {
		log.Fatalf("Get config ipdstHost error: %s", err)
	}

	m := n.bpf.redirectHTTPSMaps.ConfigMap
	if err = putMap(m, 0, kcfg); err != nil {
		log.Fatalf("Set Kernel config error: %s", err)
	}

	// debug test
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, kcfg.ipHost)
	mac := net.HardwareAddr(kcfg.macHost[:]).String()

	// debug
	v := getMap(m, 0)
	vv := (*reflect.SliceHeader)(unsafe.Pointer(&v))
	t := (*KernelConfig)(unsafe.Pointer(vv.Data))

	if t.ipHost == kcfg.ipHost &&
		t.redirectUrlLinux == kcfg.redirectUrlLinux {
		log.Printf("Set KernelConfig OK %s %v, %v %X, %s", mac, t.macHost, ip, kcfg.ipHost, string(t.redirectUrlLinux[:]))
	} else {
		log.Println("Error: Set KernelConfig ", *t, kcfg)
	}
}

func (n *redirectHTTPS) Close() {
	n.timerMetrics.Stop()

	if err := n.reader.Close(); err != nil {
		log.Fatalf("Closing perf event reader: %s", err)
	}

	n.bpf.Close()

	if err := DettachProg(n.iface); err != nil {
		log.Fatalf("Dettach Prog and iface error: %s", err)
	}
}

func (n *redirectHTTPS) LogMetrics() {
	m := n.bpf.redirectHTTPSMaps.METRICS_MAP
	v := make([]uint64, m.MaxEntries())
	getAllMap(m, v)

	log.Printf("all[%d %d], proto[%d %d %d], os[%d %d], err[%d %d %d %d %d %d]", v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], v[9], v[10], v[11], v[12])
}

func (n *redirectHTTPS) Listen() {
	log.Println("Listening for timer and dbg events..")
	log.Println("metrics count: [All, Host], [IPV4 TCP HTTP], [Linux Win], [errEth errIPV4 errTCP errHTTP]")
	log.Println("dbg: macSrc, macDst, ipSrc, ipDst, flags, ttl, DbgType, DbgInfo")

	go func() {
		for {
			select {
			case <-n.timerMetrics.C:
				n.LogMetrics()
				n.timerMetrics.Reset(n.timerInterval)
			}
		}
	}()

	for {
		record, err := n.reader.Read()
		if err != nil {
			if perf.IsClosed(err) {
				return
			}
			log.Printf("Reading from perf event reader: %s", err)
		}
		n.HandleRecord(record)
	}
}

func (n *redirectHTTPS) HandleRecord(record perf.Record) {
	if record.LostSamples != 0 {
		log.Printf("Perf event ring buffer full, dropped %d samples", record.LostSamples)
		return
	}

	var e Event
	err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &e)
	if err != nil {
		log.Printf("Parsing perf event: %s", err)
		return
	}

	os := "Windows"
	if e.DbgType == 5 {
		os = "Linux"
	}
	src, dst := int2ip(e.Saddr).String(), int2ip(e.Daddr).String()
	log.Printf("%s: ip[%s %s], flags[%X, %d], dbg[%d, %d]", os, src, dst, e.Flags, e.Ttl, e.DbgType, e.DbgInfo)
}

// self.os_table = {
// 	(64, 5840)  : "Linux (kernel 2.4 and 2.6)",
// 	(64, 64240) : "Linux",
// 	(64, 5720)  : "Google's customized Linux",
// 	(64, 65535) : "FreeBSD or Mac OS",
// 	(128, 65535): "Windows XP or Windows 10",
// 	(128, 8192) : "Windows 7, Vista and Server 2008",
// 	(128, 64240): "Windows 10",
// 	(255, 4128) : "Cisco Router (IOS 12.4)",
// }

func (n *redirectHTTPS) HttpsCaptialRedirect(record perf.Record) {
	// p := Params{
	// 	ip:   ipSwith,
	// 	port: 161,
	// version: g.Version2c, // ignore, TODO hide in Snmp{}
	// }
	// s := NewSnmp(p)
	// DownUpIface(ipPC)
	// snmpscan(ipSwitch)
}
