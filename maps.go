package main

import (
	"github.com/cilium/ebpf"
)

func clearMap(m *ebpf.Map) {
	var nextKey uint32 = 0
	deleteKeys := make([]uint32, m.MaxEntries())
	deleteValues := make([]uint32, m.MaxEntries())

	count, err := m.BatchLookupAndDelete(nil, &nextKey, deleteKeys, deleteValues, nil)
	if err != nil {
		log.Println("BatchLookUpDelete:", "count", count, "Err", err.Error())
	}
}

func putMap(m *ebpf.Map, key uint32, value interface{}) (err error) {
	if err = m.Put(key, value); err != nil {
		log.Println("MAP put failed", m.String(), err)
	}
	return
}

func getMap(m *ebpf.Map, key uint32) []byte {
	value, err := m.LookupBytes(&key)
	if err != nil {
		log.Println("map BatchLookup", err)
	}
	return value
}

func getAllMap(m *ebpf.Map, values interface{}) []uint32 {
	var nextKey uint32 = 0
	lookupKeys := make([]uint32, m.MaxEntries())

	count, err := m.BatchLookup(nil, &nextKey, lookupKeys, values, nil)
	if err != nil {
		log.Println("map BatchLookup", err)
	}
	return lookupKeys[:count]
}
