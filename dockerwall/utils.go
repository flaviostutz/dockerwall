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
	ipsetNameRegex, _ := regexp.Compile("Name: (.*)\n")
	ipsetNames := ipsetNameRegex.FindAllStringSubmatch(listStr, -1)
	ipsetMembersRegex, _ := regexp.Compile("(?sU)Members:\n(.*)\n\n")
	ipsetMembers := ipsetMembersRegex.FindAllStringSubmatch(fmt.Sprintf("%s\n\n", listStr), -1)

	// logrus.Debugf(">>>>> ipsetNames %v", ipsetNames)
	// logrus.Debugf(">>>>> ipsetMembers %v", ipsetMembers)

	ipsetMap := make(map[string]dsutils.TTLCollection)
	for i, ipsetName := range ipsetNames {

		ipsetIps := strings.Split(ipsetMembers[i][1], "\n")
		// logrus.Debugf("IPSET %s - %v", ipsetName[1], ipsetIps)

		containerIDRegex, _ := regexp.Compile("(.*)-dst")
		containerIDResult := containerIDRegex.FindAllStringSubmatch(ipsetName[1], -1)
		if len(containerIDResult) == 1 {
			containerID := containerIDResult[0][1]
			addIPToIpsetMap(ipsetMap, containerID, ipsetIps)
		}

	}
	logrus.Debugf("ipsetMap from actual IPSET=%v", ipsetMap)
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
