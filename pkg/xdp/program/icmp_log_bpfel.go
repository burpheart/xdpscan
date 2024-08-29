// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || arm || arm64 || loong64 || mips64le || mipsle || ppc64le || riscv64

package program

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadIcmp_log returns the embedded CollectionSpec for icmp_log.
func loadIcmp_log() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_Icmp_logBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load icmp_log: %w", err)
	}

	return spec, err
}

// loadIcmp_logObjects loads icmp_log and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*icmp_logObjects
//	*icmp_logPrograms
//	*icmp_logMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadIcmp_logObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadIcmp_log()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// icmp_logSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type icmp_logSpecs struct {
	icmp_logProgramSpecs
	icmp_logMapSpecs
}

// icmp_logSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type icmp_logProgramSpecs struct {
	XdpProg *ebpf.ProgramSpec `ebpf:"xdp_prog"`
}

// icmp_logMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type icmp_logMapSpecs struct {
	PerfMap *ebpf.MapSpec `ebpf:"perf_map"`
}

// icmp_logObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadIcmp_logObjects or ebpf.CollectionSpec.LoadAndAssign.
type icmp_logObjects struct {
	icmp_logPrograms
	icmp_logMaps
}

func (o *icmp_logObjects) Close() error {
	return _Icmp_logClose(
		&o.icmp_logPrograms,
		&o.icmp_logMaps,
	)
}

// icmp_logMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadIcmp_logObjects or ebpf.CollectionSpec.LoadAndAssign.
type icmp_logMaps struct {
	PerfMap *ebpf.Map `ebpf:"perf_map"`
}

func (m *icmp_logMaps) Close() error {
	return _Icmp_logClose(
		m.PerfMap,
	)
}

// icmp_logPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadIcmp_logObjects or ebpf.CollectionSpec.LoadAndAssign.
type icmp_logPrograms struct {
	XdpProg *ebpf.Program `ebpf:"xdp_prog"`
}

func (p *icmp_logPrograms) Close() error {
	return _Icmp_logClose(
		p.XdpProg,
	)
}

func _Icmp_logClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed icmp_log_bpfel.o
var _Icmp_logBytes []byte