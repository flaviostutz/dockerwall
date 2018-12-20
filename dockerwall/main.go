package main

import (
	"flag"
	"os"
	"strings"
	"sync"

	"github.com/Sirupsen/logrus"
	"github.com/docker/docker/client"
)

func main() {
	logLevel := flag.String("loglevel", "debug", "debug, info, warning, error")
	gatewayNetworks := flag.String("gateway-networks", "", "Docker networks whose gateway access will be managed by DockerWall. If empty, all bridge networks will be used")
	defaultOutbound := flag.String("default-outbound", "_dns_", "Domains and IPs that will be allowed by default. Use '_dns_' to allow access to local dns server ip")
	flag.Parse()

	switch *logLevel {
	case "debug":
		logrus.SetLevel(logrus.DebugLevel)
		break
	case "warning":
		logrus.SetLevel(logrus.WarnLevel)
		break
	case "error":
		logrus.SetLevel(logrus.ErrorLevel)
		break
	default:
		logrus.SetLevel(logrus.InfoLevel)
	}

	logrus.Infof("====Starting Dockerwall %s====")

	cli, err := client.NewClientWithOpts(client.WithVersion("1.38"))
	if err != nil {
		logrus.Errorf("Error creating Docker client instance. err=%s", err)
		return
	}

	gatewayNets := make([]string, 0)
	skipNets := make([]string, 0)
	if *gatewayNetworks != "" {
		gn := strings.Split(*gatewayNetworks, ",")
		for _, v := range gn {
			if len(v) > 1 {
				if v[0] == '!' {
					skipNets = append(skipNets, v[1:])
				} else {
					gatewayNets = append(gatewayNets, v)
				}
			}
		}
	}

	swarmWaller := Waller{
		dockerClient:       cli,
		useDefaultNetworks: (len(gatewayNets) == 0),
		gatewayNetworks:    gatewayNets,
		defaultOutbound:    *defaultOutbound,
		skipNetworks:       skipNets,
		currentMetrics:     "",
		m:                  &sync.Mutex{},
	}

	swarmWaller.init()
	err = swarmWaller.startup()
	if err != nil {
		logrus.Errorf("Startup error. Exiting. err=%s", err)
		os.Exit(1)
	}

}
