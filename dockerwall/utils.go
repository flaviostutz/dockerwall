package dockerwall

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/flaviostutz/dsutils"
	"github.com/flaviostutz/osutils"
	"github.com/sirupsen/logrus"
)

func getContainerOutboundDomainNames(container types.Container) string {
	domainNames := ""
	for k, v := range container.Labels {
		if k == "dockerwall.outbound" {
			domainNames = domainNames + "," + v
			break
		}
	}
	return domainNames
}

func ipsetMapFromCurrentIPSET() (map[string]dsutils.TTLCollection, error) {
	logrus.Debugf("Getting current IPSET groups")
	listStr, err1 := osutils.ExecShellf("ipset -L")
	if err1 != nil {
		logrus.Errorf("Couldn't list ipset groups. err=%s", err1)
		return nil, err1
	}
	ipsetRegex, _ := regexp.Compile("(?Us)Name: ([A-Za-z0-9]*)-dst.*Members:(.*)\n\n")
	ipsetGroups := ipsetRegex.FindAllStringSubmatch(fmt.Sprintf("%s\n\n\n", listStr), -1)

	// fmt.Printf(">>>>> listStr\n%s", fmt.Sprintf("%s\n\n", listStr))
	// fmt.Printf(">>>>> ipsetGroups\n%v", ipsetGroups)

	ipsetMap := make(map[string]dsutils.TTLCollection)
	for _, ipsetGroup := range ipsetGroups {

		containerID := ipsetGroup[1]
		ipsetIpsStr := ipsetGroup[2]

		ipsetIps := strings.Split(ipsetIpsStr, "\n")
		if len(ipsetIps) > 0 {
			ipsetIps = ipsetIps[1:]
		}
		// logrus.Debugf("IPSET %s - %v", containerID, ipsetIps)

		if len(ipsetIps) > 0 {
			addIPToIpsetMap(ipsetMap, containerID, ipsetIps)
		}
	}
	// logrus.Debugf("ipsetMap from actual IPSET=%v", ipsetMap)
	for k, v := range ipsetMap {
		logrus.Debugf("IPSET MAP %s - %v", k, v.List())
	}
	return ipsetMap, nil
}

func addIPToIpsetMap(ipsetMap map[string]dsutils.TTLCollection, containerID string, ips []string) {
	m, exists := ipsetMap[containerID]
	if !exists {
		logrus.Debugf("ipsetMap doesn't exist for container. creating %s", containerID)
		m = dsutils.NewTTLCollection(float32(30 * 24 * 3600))
		ipsetMap[containerID] = m
	}
	for _, ip := range ips {
		logrus.Debugf("adding element to ipsetmap. containerID=%s. ip=%s", containerID, ip)
		m.Add(ip)
	}
	ipsetMap[containerID] = m
}
