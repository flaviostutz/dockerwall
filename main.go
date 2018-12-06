package main

import (
	_ "errors"
	_ "flag"
	"fmt"
	_ "log"
	_ "os"
	_ "os/signal"
	_ "path/filepath"
	_ "syscall"

	_ "github.com/Sirupsen/logrus"
	_ "github.com/docker/docker/api/types"
	_ "github.com/docker/docker/api/types/events"
	_ "github.com/docker/docker/client"
	_ "github.com/go-cmd/cmd"
)

func main() {
	fmt.Println("This is used for build caching purposes. Should be replaced.")
}
