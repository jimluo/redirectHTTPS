package main

import (
	"errors"
	"net"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
)

// attachProgram attaches the given XDP program to the network interface.
func AttachProg(prog_fd int, iface *net.Interface) error {
	if err := DettachProg(iface); err != nil {
		log.Println("error: DettachProg")
		return err
	}

	link, err := netlink.LinkByIndex(iface.Index)
	if err != nil {
		log.Println("error: LinkByIndex")
		return err
	}
	// unix.XDP_FLAGS_UPDATE_IF_NOEXIST,unix.XDP_FLAGS_DRV_MODE, unix.XDP_FLAGS_HW_MODE, unix.XDP_FLAGS_SKB_MODE,
	return netlink.LinkSetXdpFdWithFlags(link, prog_fd, 0) //unix.XDP_FLAGS_UPDATE_IF_NOEXIST)
}

// removeProgram removes an existing XDP program from the given network interface.
func DettachProg(iface *net.Interface) error {
	const tryRepeatCount = 2
	for i := 0; i < tryRepeatCount; i++ {
		link, err := netlink.LinkByIndex(iface.Index)
		if err != nil {
			return err
		}
		a := link.Attrs()
		if a == nil || a.Xdp == nil || !a.Xdp.Attached {
			break
		}
		if err = netlink.LinkSetXdpFd(link, -1); err != nil {
			return errors.New("LinkSetXdpFd() failed:" + err.Error())
		}
		time.Sleep(time.Second)
	}

	return nil
}

func GetIface(linkname string) *net.Interface {
	interfaces, err := net.Interfaces()
	if err != nil {
		log.Println("error: failed to fetch the list of network interfaces on the system: ", err.Error())
		return nil
	}

	for _, iface := range interfaces {
		if iface.Name == linkname {
			return &iface
		}
	}

	log.Println("error: couldn't find a suitable network interface to attach to")

	return nil
}

func LoadProg(prog_fd int, linkname string) *net.Interface {
	// Allow the current process to lock memory for eBPF resources.
	err := rlimit.RemoveMemlock()
	if err != nil {
		log.Fatal("rlimit.RemoveMemlock()", err)
		panic("rlimit.RemoveMemlock()")
	}

	iface := GetIface(linkname)
	if iface == nil {
		panic("error: network interface not found")
	}

	err = AttachProg(prog_fd, iface)
	if err != nil {
		log.Fatal("AttachProg() ", err, prog_fd, iface)
		panic("AttachProg() " + err.Error())
	}

	return iface
}
