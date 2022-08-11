package main

import (
	"context"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	log_prefixed "github.com/chappjc/logrus-prefix"
	"github.com/rifflock/lfshook"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go  -target "bpfel" redirectHTTPS ./bpf/redirectHTTPS.c -I/usr/include/ -I./redirectHTTPS/lib/  -- -D DEBUG -D__TARGET_ARCH_x86 -O1 -c -g
// clang -S -target bpf -D __BPF_TRACING__ -D DEBUG -Wall -Werror -emit-llvm -O1 -c -g -o redirectHTTPS.bpf redirectHTTPS.c

type (
	Config struct {
		Ifname           string        `yaml:"ifname"`
		MetricsInterval  time.Duration `yaml:"metricsInterval`
		RedirectUrlLinux string        `yaml:"redirectUrlLinux"`
	}
)

var log *logrus.Entry

// GetLogger returns a configured logger instance
func GetLogger(prefix string) *logrus.Entry {
	logger := logrus.New()
	logger.SetFormatter(&log_prefixed.TextFormatter{
		FullTimestamp: true,
	})
	logger.SetLevel(logrus.DebugLevel)
	logger.AddHook(lfshook.NewHook(prefix+".log", &logrus.TextFormatter{}))
	// logger.SetOutput(ioutil.Discard)

	return logger.WithField("prefix", prefix)
}

// Read the config file from the current directory and marshal into the conf config struct.
func LoadConfig(fname string) *Config {
	viper.AddConfigPath("./")
	viper.SetConfigName(fname)

	if err := viper.ReadInConfig(); err != nil {
		log.Printf("%v", err)
	}

	conf := &Config{}
	if err := viper.Unmarshal(conf); err != nil {
		log.Printf("unable to decode into config struct, %v", err)
	}

	log.Printf("conf: %v", conf)

	return conf
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	filename := filepath.Base(os.Args[0])
	log = GetLogger(filename)

	cfg := LoadConfig("config")
	log.Println("config: ", cfg)

	redirectHTTPS := NewredirectHTTPS(cfg)
	redirectHTTPS.SetKernelConfig()

	go func() {
		<-ctx.Done()
		redirectHTTPS.Close()
	}()

	redirectHTTPS.Listen()

	redirectHTTPS.Close()
}
