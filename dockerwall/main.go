package main

import (
	"flag"

	"github.com/Sirupsen/logrus"
	"github.com/docker/docker/client"
)

const VERSION = "1.0.0-beta"

func main() {
	versionFlag := flag.Bool("version", false, "Print version")
	logLevel := flag.String("loglevel", "debug", "debug, info, warning, error")
	// lockTimeoutMillis := flag.Uint64("lock-timeout", 10*1000, "If a host with a mounted device stops sending lock refreshs, it will be release to another host to mount the image after this time")
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

	if *versionFlag {
		logrus.Infof("%s\n", VERSION)
		return
	}

	logrus.Infof("====Starting Dockerwall %s====", VERSION)

	cli, err := client.NewEnvClient()
	if err != nil {
		logrus.Errorf("Error creating Docker client instance. err=%s", err)
		return
	}

	swarmWaller := Waller{
		dockerClient: cli,
	}

	err = swarmWaller.startup()
	if err != nil {
		logrus.Errorf("Startup error. Exiting. err=%s", err)
	}

}
