package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/gosnmp/gosnmp"
	g "github.com/gosnmp/gosnmp"
)

type (
	Snmp struct {
		snmp         *g.GoSNMP
		MnemonicOids map[string]string
		ifaceMap     map[string]*Iface
		sysName      string
		sysDescr     string
	}
	Iface struct {
		ip   string
		mac  string
		idx  int
		isUp bool
	}
	Params struct {
		ip         string
		port       uint16
		version    g.SnmpVersion
		username   string
		passwdAuth string
		passwdPriv string
	}
)

func NewSnmp(p Params) *Snmp {
	s := &Snmp{
		snmp: &g.GoSNMP{
			Target:    p.ip,
			Port:      p.port,
			Community: "public",
			Version:   p.version,
			// Logger:             g.NewLogger(log.New(os.Stdout, "", 0)),
			Timeout:            time.Duration(2) * time.Second,
			Retries:            3,
			ExponentialTimeout: true,
			MaxOids:            10,
		},
	}

	if p.version == g.Version3 {
		s.snmp.SecurityParameters = &g.UsmSecurityParameters{
			UserName:                 p.username,
			AuthenticationProtocol:   g.SHA,
			AuthenticationPassphrase: p.passwdAuth,
			PrivacyProtocol:          g.DES,
			PrivacyPassphrase:        p.passwdPriv,
		}
	}

	s.MnemonicOids = map[string]string{
		"sysName":  "1.3.6.1.2.1.1.5.0",
		"sysDescr": "1.3.6.1.2.1.1.1.0",
		"ifNumber": "1.3.6.1.2.1.2.1",
		// "ifDescr":       "1.3.6.1.2.1.2.2.1.2", // name
		// "ifPhysAddress": "1.3.6.1.2.1.2.2.1.6", // mac
		// // "ipAddrTable":   "1.3.6.1.2.1.4.20",    // ip
		// "ipAdEntAddr": "1.3.6.1.2.1.4.20.1.1",

		"ifIndex":       "1.3.6.1.2.1.2.2.1.1", //桥接端口对应的端口
		"ifAdminStatus": "1.3.6.1.2.1.2.2.1.7", //接口的管理状态
		"ifOperStatus":  "1.3.6.1.2.1.2.2.1.8", //接口的操作状态

		//ifSpecific   MIB引用定义，指向一个用于实现该网络接口的特定介质类型
		"atIfIndex":     "1.3.6.1.2.1.3.1.1.1", //指向每个特定映射IP
		"atPhysAddress": "1.3.6.1.2.1.3.1.1.2", //映射IP介质相关的物理地址
		//atNetAddress 介质相关物理地址所关联的IP地址

		// "ipAdEntAddr": "1.3.6.1.2.1.4.20.1.1",
		// "ipRouteDest": "1.3.6.1.2.1.4.21.1.1",
	}

	s.ifaceMap = make(map[string]*Iface)

	return s
}

func (s *Snmp) Connect() error {
	err := s.snmp.Connect()
	if err != nil {
		log.Fatalf("Connect() err: %v", err)
	}

	// Function handles for collecting metrics on query latencies.
	// var sent time.Time
	// s.snmp.OnSent = func(x *g.GoSNMP) {
	// 	sent = time.Now()
	// }
	// s.snmp.OnRecv = func(x *g.GoSNMP) {
	// 	log.Println("Query latency in seconds:", time.Since(sent).Seconds())
	// }

	return err
}

func (s *Snmp) Var2Str(v *g.SnmpPDU) (str string) {
	switch v.Type {
	case g.OctetString:
		str = string(v.Value.([]byte))
	default:
		str = g.ToBigInt(v.Value).String()
	}
	return
}

func (s *Snmp) DeviceInfo(oidnames ...string) error {
	oids := make([]string, 0, len(oidnames))
	for _, v := range oidnames {
		oids = append(oids, s.MnemonicOids[v])
	}
	result, err := s.snmp.Get(oids)
	if err != nil {
		log.Fatalf("Get() err: %v", err)
	}

	s.sysName = s.Var2Str(&result.Variables[0])
	s.sysDescr = s.Var2Str(&result.Variables[1])

	return err
}

// iso.3.6.1.2.1.3.1.1.1.7.1.203.170.27.17 = INTEGER: 7
// iso.3.6.1.2.1.3.1.1.1.7.1.203.170.27.18 = INTEGER: 7
// iso.3.6.1.2.1.3.1.1.1.8.1.94.102.168.14 = INTEGER: 8
// iso.3.6.1.2.1.3.1.1.1.8.1.94.102.168.15 = INTEGER: 8
// iso.3.6.1.2.1.3.1.1.2.7.1.203.170.27.17 = Hex-STRING: 00 10 DB FF 20 80
// iso.3.6.1.2.1.3.1.1.2.7.1.203.170.27.18 = Hex-STRING: 00 1D A1 4B FB 9A
// iso.3.6.1.2.1.3.1.1.2.8.1.94.102.168.14 = Hex-STRING: 02 01 11 04 03 36
// iso.3.6.1.2.1.3.1.1.2.8.1.94.102.168.15 = Hex-STRING: 00 1D A1 4B FB 9B
func (s *Snmp) QueryIfaces() error {
	prefixLen := len(".1.3.6.1.2.1.3.1.1.1.7.1.")
	prefixIdx := s.MnemonicOids["ifAdminStatus"]

	ifaceMap := s.ifaceMap
	idxSet := make(map[string]bool)
	for i, n := range []string{"atIfIndex", "atPhysAddress"} {
		result, err := s.snmp.WalkAll(s.MnemonicOids[n])
		if err != nil {
			log.Printf("Walk(%s) err: %v", n, err)
		}
		for _, v := range result {
			k := v.Name[prefixLen:]
			iface, ok := ifaceMap[k]
			if !ok {
				iface = &Iface{ip: k}
			}
			if i == 0 {
				iface.idx = int(g.ToBigInt(v.Value).Uint64())
				kIdx := fmt.Sprintf("%s.%d", prefixIdx, iface.idx)
				idxSet[kIdx] = true
			} else if i == 1 {
				iface.mac = hex.EncodeToString(v.Value.([]byte))
			}
			// log.Println(i, k, iface)
			ifaceMap[k] = iface
		}
	}

	idxOids := []string{}
	for k, _ := range idxSet {
		idxOids = append(idxOids, k)
	}
	log.Println(idxOids)
	result, err := s.snmp.Get(idxOids)
	if err != nil {
		log.Fatalf("Get() err: %v", err)
	}

	for _, v := range result.Variables {
		idx, err := strconv.Atoi(v.Name[len(v.Name)-1:])
		if err != nil {
			log.Println(err)
		}
		stateIdx := int(g.ToBigInt(v.Value).Uint64())
		for _, iface := range ifaceMap {
			if iface.idx == idx {
				iface.isUp = (stateIdx == 1)
			}
			// log.Println(iface.idx, idx, stateIdx, iface)
		}
	}

	return err
}

// snmpget -v 2c -c public 127.0.0.1 1.3.6.1.2.1.2.2.1.7.5  integer 1
func (s *Snmp) controlIface(ip, mac string, isUp bool) {
	iface, ok := s.ifaceMap[ip]
	if !ok {
		for _, v := range s.ifaceMap {
			if v.mac == mac {
				iface = v
				break
			}
		}
	}

	action := 2
	if isUp {
		action = 1
	}
	prefixIdx := s.MnemonicOids["ifAdminStatus"]
	oid := g.SnmpPDU{
		Name:  prefixIdx + strconv.Itoa(iface.idx),
		Type:  gosnmp.Integer,
		Value: action,
	}
	pdus := []g.SnmpPDU{oid}
	result, err := s.snmp.Set(pdus)
	if err != nil {
		log.Fatalf("Set(UpIface) err: %v", err)
	}
	r := result.Variables[0]
	log.Printf("string: %s\n", string(r.Value.([]byte)))
}

// snmpget -v 2c -c public 127.0.0.1 1.3.6.1.2.1.2.2.1.7.5  integer 1
func (s *Snmp) UpIface(ip, mac string) {
	s.controlIface(ip, mac, true)
}

// snmpset -v 2c -c public 127.0.0.1 1.3.6.1.2.1.2.2.1.7.5  integer 2
func (s *Snmp) DownIface(ip, mac string) {
	s.controlIface(ip, mac, false)
}

func DownUpIface(ipPC string) {
	ipSwitch, err := TraceGateway(ipPC)
	if err != nil {
		return
	}
	p := Params{
		ip:      ipSwitch.String(),
		port:    161,
		version: g.Version2c,
	}
	s := NewSnmp(p)
	err = s.Connect()
	if err != nil {
		log.Printf("Connet error: %s\n", err)
	}
	defer s.snmp.Conn.Close()

	s.DeviceInfo("sysName", "sysDescr") //, "ifDescr", "ipAdEntAddr")
	s.QueryIfaces()

	log.Println(s)

	iface, ok := s.ifaceMap[ipPC]
	if ok {
		s.DownIface(iface.ip, iface.mac)
		time.Sleep(time.Microsecond * 100) //
		s.UpIface(iface.ip, iface.mac)
	}
}

func TraceGateway(ipPC string) (net.IP, error) {
	hops, err := Trace(net.ParseIP(ipPC))
	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	nodes := hops[len(hops)-2].Nodes
	ipSwitch := nodes[len(nodes)-1].IP
	log.Println(ipSwitch)
	return ipSwitch, nil
}

func snmpscan(ipSwith string) {
	if ipSwith == "" {
		ipSwith = "127.0.0.1"
	}
	p := Params{
		ip:      ipSwith,
		port:    161,
		version: g.Version2c,
	}
	s := NewSnmp(p)
	err := s.Connect()
	if err != nil {
		log.Printf("Connet error: %s\n", err)
	}
	defer s.snmp.Conn.Close()

	s.DeviceInfo("sysName", "sysDescr") //, "ifDescr", "ipAdEntAddr")
	s.QueryIfaces()

	log.Println(s)
}
