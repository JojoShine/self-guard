//go:build linux

package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

// Conditional branches use adjacent long jumps, avoiding cBPF's 8-bit branch
// range when an authorized scope contains multiple IPv6 networks and VLANs.
type monitorFilterBuilder struct {
	code   []syscall.SockFilter
	labels map[string]int
	jumps  map[int]string
}

func (b *monitorFilterBuilder) add(code uint16, k uint32) {
	b.code = append(b.code, syscall.SockFilter{Code: code, K: k})
}
func (b *monitorFilterBuilder) mark(label string) { b.labels[label] = len(b.code) }
func (b *monitorFilterBuilder) jump(label string) { b.jumps[len(b.code)] = label; b.add(0x05, 0) }
func (b *monitorFilterBuilder) equal(value uint32, yes, no string) {
	b.code = append(b.code, syscall.SockFilter{Code: 0x15, K: value, Jf: 1})
	b.jump(yes)
	b.jump(no)
}
func trafficMonitorFilter(c TrafficCaptureConfig) ([]syscall.SockFilter, error) {
	// IPv4-mapped IPv6 prefixes have cross-family net.IP.Contains semantics.
	// Leave their CIDR test to userspace rather than risk narrowing that scope.
	for _, cidr := range c.CIDRs {
		ip, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, err
		}
		_, bits := network.Mask.Size()
		if bits == 128 && ip.To4() != nil {
			c.CIDRs = nil
			break
		}
	}
	b := monitorFilterBuilder{labels: map[string]int{}, jumps: map[int]string{}}
	for depth := 0; depth <= 2; depth++ {
		label := fmt.Sprintf("ether%d", depth)
		b.mark(label)
		b.add(0x28, uint32(12+4*depth))
		b.equal(0x0800, fmt.Sprintf("ipv4_%d", depth), label+"v6")
		b.mark(label + "v6")
		b.equal(0x86dd, fmt.Sprintf("ipv6_%d", depth), label+"vlan")
		b.mark(label + "vlan")
		if depth == 2 {
			b.jump("reject")
			continue
		}
		next := fmt.Sprintf("ether%d", depth+1)
		b.equal(0x8100, next, label+"qinq")
		b.mark(label + "qinq")
		b.equal(0x88a8, next, "reject")
	}
	for depth := 0; depth <= 2; depth++ {
		for _, version := range []int{4, 6} {
			prefix := fmt.Sprintf("ipv%d_%d", version, depth)
			off := 14 + 4*depth
			b.mark(prefix)
			protocolOffset := off + 9
			if version == 6 {
				protocolOffset = off + 6
			}
			b.add(0x30, uint32(protocolOffset))
			if c.Protocol == "TCP" {
				b.equal(6, prefix+"addresses", "reject")
			} else if c.Protocol == "UDP" {
				b.equal(17, prefix+"addresses", "reject")
			} else {
				b.equal(6, prefix+"addresses", prefix+"udp")
				b.mark(prefix + "udp")
				b.equal(17, prefix+"addresses", "reject")
			}
			b.mark(prefix + "addresses")
			// IPv6 can contain IPv4-mapped endpoints; net.IP.Contains normalizes
			// those across families. Keep IPv6 CIDR checks in userspace to avoid
			// dropping an authorized mapped endpoint in the kernel.
			if len(c.CIDRs) > 0 && version == 4 {
				for i, cidr := range c.CIDRs {
					ip, network, err := net.ParseCIDR(cidr)
					if err != nil {
						return nil, err
					}
					ipv4 := ip.To4() != nil
					if (version == 4) != ipv4 {
						continue
					}
					address := network.IP
					mask := network.Mask
					words := 4
					source := off + 8
					destination := off + 24
					if ipv4 {
						address = address.To4()
						words = 1
						source = off + 12
						destination = off + 16
					}
					for side, position := range []int{source, destination} {
						start := fmt.Sprintf("%snet%dside%d", prefix, i, side)
						next := start + "next"
						for word := 0; word < words; word++ {
							b.add(0x20, uint32(position+word*4))
							b.add(0x54, binary.BigEndian.Uint32(mask[word*4:word*4+4]))
							yes := fmt.Sprintf("%sword%d", start, word)
							if word == words-1 {
								yes = prefix + "ports"
							}
							b.equal(binary.BigEndian.Uint32(address[word*4:word*4+4]), yes, next)
							if word < words-1 {
								b.mark(yes)
							}
						}
						b.mark(next)
					}
				}
				b.jump("reject")
			}
			b.mark(prefix + "ports")
			if version == 4 {
				b.add(0xb1, uint32(off))
			} // X = IPv4 header length, including options.
			for side := 0; side < 2; side++ {
				if version == 4 {
					b.add(0x48, uint32(off+side*2))
				} else {
					b.add(0x28, uint32(off+40+side*2))
				}
				for i, port := range c.Ports {
					next := fmt.Sprintf("%sport%d_%d", prefix, side, i)
					b.equal(uint32(port), "accept", next)
					b.mark(next)
				}
			}
			b.jump("reject")
		}
	}
	b.mark("accept")
	b.add(0x06, 65536)
	b.mark("reject")
	b.add(0x06, 0)
	if len(b.code) > 4096 {
		return nil, fmt.Errorf("monitor filter exceeds kernel instruction budget")
	}
	for index, label := range b.jumps {
		target, ok := b.labels[label]
		if !ok || target <= index {
			return nil, fmt.Errorf("invalid monitor filter branch")
		}
		b.code[index].K = uint32(target - index - 1)
	}
	return b.code, nil
}
func attachTrafficMonitorFilter(fd int, c TrafficCaptureConfig) error {
	code, err := trafficMonitorFilter(c)
	if err != nil {
		return err
	}
	program := syscall.SockFprog{Len: uint16(len(code)), Filter: &code[0]}
	_, _, errno := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(fd), syscall.SOL_SOCKET, syscall.SO_ATTACH_FILTER, uintptr(unsafe.Pointer(&program)), unsafe.Sizeof(program), 0)
	if errno != 0 {
		return fmt.Errorf("monitor kernel filter unavailable: %w", errno)
	}
	return nil
}
