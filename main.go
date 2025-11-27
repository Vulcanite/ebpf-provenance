package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esutil"
)

type ESConfig struct {
	Host       string `json:"es_host"`
	Port       int    `json:"es_port"`
	User       string `json:"es_user"`
	Password   string `json:"es_password"`
	Index      string `json:"es_index"`
	BatchSize  int    `json:"batch_size"`
	SslEnabled bool   `json:"secure"`
}

type Config struct {
	EventsDir   string   `json:"events_dir"`
	StorageType string   `json:"storage_type"`
	ESConfig    ESConfig `json:"es_config"`
}

type AuditEvent struct {
	TimestampNs int64  `json:"timestamp_ns"`
	Datetime    string `json:"datetime"`
	Pid         uint32 `json:"pid"`
	Ppid        uint32 `json:"ppid"`
	Uid         uint32 `json:"uid"`
	Comm        string `json:"comm"`
	Syscall     string `json:"syscall"`
	Filename    string `json:"filename"`
	Fd          int64  `json:"fd"`
	Ret         int64  `json:"ret"`
	Error       string `json:"error,omitempty"`
	ErrorCode   int64  `json:"error_code,omitempty"`
	DestIP      string `json:"dest_ip,omitempty"`
	DestIPv6    string `json:"dest_ipv6,omitempty"`
	DestPort    uint16 `json:"dest_port,omitempty"`
	SaFamily    string `json:"sa_family,omitempty"`
	Count       uint64 `json:"count,omitempty"`
	BytesRW     int64  `json:"bytes_rw,omitempty"`
}

var (
	outputFile  *os.File
	fileLock    sync.Mutex
	bulkIndexer esutil.BulkIndexer
	cfg         Config
)

func int8ToStr(bs []int8) string {
	b := make([]byte, len(bs))
	for i, v := range bs {
		if v == 0 {
			return string(b[:i])
		}
		b[i] = byte(v)
	}
	return string(b)
}

func parseIPv4(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
}

func parseIPv6(parts [4]uint32) string {
	buf := new(bytes.Buffer)
	for _, p := range parts {
		binary.Write(buf, binary.BigEndian, p)
	}
	return net.IP(buf.Bytes()).String()
}

func getErrno(ret int64) (string, int64) {
	if ret >= 0 {
		return "", 0
	}
	errCode := -ret
	return fmt.Sprintf("ERR_%d", errCode), errCode
}

func setupLogging() {
	if cfg.EventsDir == "" {
		cfg.EventsDir = "/var/monitoring/events"
	}

	os.MkdirAll(cfg.EventsDir, 0755)

	path := fmt.Sprintf("%s/events.jsonl", cfg.EventsDir)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}

	outputFile = f
	fmt.Printf("[+] Local logging: %s\n", path)
}

func setupES() {
	protocol := "http"
	if cfg.ESConfig.SslEnabled {
		protocol = "https"
	}

	// Sanitize Host: Remove protocol if user added it in JSON to avoid "https://https://..."
	host := cfg.ESConfig.Host
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimPrefix(host, "https://")

	url := fmt.Sprintf("%s://%s:%d", protocol, host, cfg.ESConfig.Port)
	fmt.Printf("[*] Connecting to Elasticsearch at %s ...\n", url)

	es, err := elasticsearch.NewClient(elasticsearch.Config{
		Addresses: []string{url},
		Username:  cfg.ESConfig.User,
		Password:  cfg.ESConfig.Password,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	})

	if err != nil {
		log.Printf("[!] ES Client Create Failed: %v", err)
		return
	}

	// 1. VERIFY CONNECTION NOW (Fail Fast)
	info, err := es.Info()
	if err != nil {
		log.Printf("[!] ES Connection Failed: %v", err)
		log.Printf("[!] Check your Password, Host, and SSL settings in config.json")
		return
	}
	defer info.Body.Close()
	fmt.Printf("[+] Connected to ES: %s\n", info.Status())

	bi, err := esutil.NewBulkIndexer(esutil.BulkIndexerConfig{
		Client:        es,
		Index:         cfg.ESConfig.Index,
		FlushBytes:    1000000, // 1MB
		FlushInterval: 1 * time.Second,
		OnError: func(ctx context.Context, err error) {
			log.Printf("[!] Bulk Indexer Error: %v", err)
		},
	})

	if err != nil {
		log.Printf("[!] Bulk Indexer Init Failed: %v", err)
		return
	}

	bulkIndexer = bi
	fmt.Println("[+] Bulk Indexer Ready")
}

func main() {
	configPath := "/var/config.json"
	data, err := os.ReadFile(configPath)
	if err != nil {
		log.Fatalf("[!] Config not found at %s", configPath)
	}
	json.Unmarshal(data, &cfg)

	setupLogging()
	if strings.EqualFold(cfg.StorageType, "elasticsearch") {
		setupES()
	}

	// SIGHUP for Logrotate
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for sig := range sigChan {
			if sig == syscall.SIGHUP {
				fmt.Println("[*] SIGHUP: Rotating logs...")
				fileLock.Lock()
				outputFile.Close()
				setupLogging()
				fileLock.Unlock()
			} else {
				fmt.Println("\n[!] Stopping...")
				os.Exit(0)
			}
		}
	}()

	// C. CO-RE: Remove Rlimit & Load Objects
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// D. Attach Tracepoints
	var links []link.Link

	attach := func(group, name string, prog *ebpf.Program) {
		l, err := link.Tracepoint(group, name, prog, nil)
		if err != nil {
			log.Printf("[!] Failed to attach %s/%s: %v", group, name, err)
			return
		}
		links = append(links, l)
	}

	attach("syscalls", "sys_enter_execve", objs.SysEnterExecve)

	attach("syscalls", "sys_enter_openat", objs.SysEnterOpenat)
	attach("syscalls", "sys_exit_openat", objs.SysExitOpenat)

	attach("syscalls", "sys_enter_openat2", objs.SysEnterOpenat2)
	attach("syscalls", "sys_exit_openat2", objs.SysExitOpenat2)

	attach("syscalls", "sys_enter_write", objs.SysEnterWrite)
	attach("syscalls", "sys_exit_write", objs.SysExitWrite)

	attach("syscalls", "sys_enter_unlinkat", objs.SysEnterUnlinkat)
	attach("syscalls", "sys_enter_connect", objs.SysEnterConnect)

	attach("syscalls", "sys_enter_clone", objs.SysEnterClone)
	attach("syscalls", "sys_enter_clone3", objs.SysEnterClone3)

	defer func() {
		for _, l := range links {
			l.Close()
		}
	}()

	fmt.Printf("[+] Monitoring started with %d probes active.\n", len(links))

	rd, err := perf.NewReader(objs.Events, os.Getpagesize()*4096)
	if err != nil {
		log.Fatalf("creating perf reader: %v", err)
	}
	defer rd.Close()

	// F. Event Loop
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}

			log.Printf("Reader error: %v", err)
			continue
		}

		if record.LostSamples > 0 {
			log.Printf("[!] Buffer full: dropped %d events", record.LostSamples)
			continue
		}

		if len(record.RawSample) < int(unsafe.Sizeof(bpfSoEvent{})) {
			log.Printf("[!] Event too small: got %d bytes, expected %d", len(record.RawSample), unsafe.Sizeof(bpfSoEvent{}))
			continue
		}

		raw := *(*bpfSoEvent)(unsafe.Pointer(&record.RawSample[0]))
		ts := time.Unix(0, int64(raw.Timestamp)).UTC()
		evt := AuditEvent{
			TimestampNs: int64(raw.Timestamp),
			Datetime:    ts.Format(time.RFC3339Nano),
			Pid:         raw.Pid,
			Ppid:        raw.Ppid,
			Uid:         raw.Uid,
			Comm:        int8ToStr(raw.Comm[:]),
			Syscall:     int8ToStr(raw.Syscall[:]),
			Filename:    int8ToStr(raw.Filename[:]),
			Fd:          raw.Fd,
			Ret:         raw.Ret,
		}

		if raw.Ret < 0 {
			evt.Error, evt.ErrorCode = getErrno(raw.Ret)
		}

		if evt.Syscall == "write" {
			evt.Count = raw.Count
			evt.BytesRW = raw.BytesRw
			if evt.Fd == 0 {
				evt.Fd = int64(raw.Flags)
			}
		}

		if evt.Syscall == "connect" {
			switch raw.SaFamily {
			case 2:
				evt.DestIP = parseIPv4(raw.DestIp)
				evt.DestPort = raw.DestPort
				evt.SaFamily = "IPv4"
			case 10:
				evt.DestIPv6 = parseIPv6(raw.DestIpv6)
				evt.DestPort = raw.DestPort
				evt.SaFamily = "IPv6"
			default:
				evt.DestIP = "0.0.0.0"
				evt.SaFamily = fmt.Sprintf("%d", raw.SaFamily)
			}
		}

		// 3. Write Output
		jsonBytes, _ := json.Marshal(evt)

		// File Output
		fileLock.Lock()
		if outputFile != nil {
			outputFile.Write(jsonBytes)
			outputFile.WriteString("\n")
		}
		fileLock.Unlock()

		// ES Output
		if bulkIndexer != nil {
			bulkIndexer.Add(context.Background(), esutil.BulkIndexerItem{
				Action: "index",
				Body:   bytes.NewReader(jsonBytes),
				OnFailure: func(ctx context.Context, item esutil.BulkIndexerItem, res esutil.BulkIndexerResponseItem, err error) {
					// Logs item-level errors (e.g. mapping conflicts, 400 Bad Request)
					if err != nil {
						log.Printf("ES Index Error: %v", err)
					} else {
						log.Printf("ES Item Error: [%d] %s", res.Status, res.Error.Reason)
					}
				},
			})
		}
	}
}
