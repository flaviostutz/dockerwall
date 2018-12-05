package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"regexp"

	"github.com/Sirupsen/logrus"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
)

//Waller Label based network filter constraints
type Waller struct {
	dockerClient *client.Client
}

func (s *Waller) startup() error {
	logrus.Infof("Performing initial full filter updates for all current containers")

	err := s.updateIptablesChains()
	if err != nil {
		return fmt.Errorf("Error updating iptables basic chains, err=%s", err)
	}

	for {
		containers, err := s.dockerClient.ContainerList(context.Background(), types.ContainerListOptions{})
		if err != nil {
			logrus.Errorf("Error listing containers. err=%s", err)

		} else {
			logrus.Debug("Updating filters and domain ips")
			for _, cont := range containers {
				err = s.updateContainerFilters(cont)
				if err != nil {
					logrus.Errorf("Error updating container filter. container=%s, err=%s", cont.ID, err)
				}
			}

			logrus.Debug("Removing orphaned ipset or iptables rules")
			err = s.removeOrphans(containers)
			if err != nil {
				logrus.Errorf("Error removing orphans. err=%s", err)
			}
		}
		time.Sleep(10000 * time.Millisecond)
	}
}

func (s *Waller) removeOrphans(containers []types.Container) error {
	currentContainers, err := s.containerGwIPs()
	if err != nil {
		return err
	}
	err = s.removeOrphanRules("DOCKERWALL-ALLOW", currentContainers)
	if err != nil {
		return err
	}
	err = s.removeOrphanRules("DOCKERWALL-DENY", currentContainers)
	if err != nil {
		return err
	}
	return nil
}

func (s *Waller) removeOrphanRules(chain string, currentContainers map[string]string) error {
	logrus.Debugf("Retrieving iptables rules for %s", chain)
	rules, err1 := ExecShellf("iptables -L %s", chain)
	if err1 != nil {
		return err1
	}
	rul, err2 := linesToArray(rules)
	if err2 != nil {
		return err2
	}

	cidregex, _ := regexp.Compile("match-set (.*)-outbound src")
	lineregex, _ := regexp.Compile("^([0-9]+)")

	//invert rules order so that we can remove rules without changing the line numbers
	rul = reverseArray(rul)

	for _, v := range rul {
		cid := cidregex.FindString(v)
		if cid != "" {
			_, exists := currentContainers[cid]
			if !exists {
				line := lineregex.FindString(v)
				if line != "" {
					logrus.Debugf("Found orphan rule line %s for container %s. Removing it.", line, cid)
					_, err4 := ExecShellf("iptables -D %s %s", chain, line)
					if err4 != nil {
						logrus.Debugf("Error removing rule on line %s for container %s. err=%s", line, cid, err4)
					} else {
						logrus.Debug("Rule removed successfully")
					}
				}
			}
		}
	}
	return nil
}

func (s *Waller) updateContainerFilters(container types.Container) error {
	logrus.Debug("Running updateContainerFilters")
	//OUTBOUND DOMAIN IPs
	outboundLabelValue := ""
	for k, v := range container.Labels {
		if k == "dockerwall.outbound" {
			outboundLabelValue = v
		}
	}
	outboundLabelValue = strings.Replace(outboundLabelValue, ",", " ", 0)
	ipsetName := container.ID + "-outbound"
	s.updateIpsetIps(ipsetName, outboundLabelValue)

	logrus.Debugf("Verifying IPTABLES rules for container %s", container.ID)

	//CONTAINER GW IP
	gwIps, err := s.containerGwIPs()
	if err != nil {
		return err
	}
	srcIP, exists := gwIps[container.ID]
	if !exists {
		return fmt.Errorf("Could not find gateway IP for %s", container.ID)
	}

	//IPTABLES ALLOW
	allowRuleFound, err1 := s.findRule("DOCKERWALL-ALLOW", ipsetName)
	if err1 != nil {
		return err1
	}
	if !allowRuleFound {
		logrus.Debugf("Iptables rule not found in chain DOCKERWALL-ALLOW for %s. Creating.", ipsetName)
		_, err := ExecShellf("iptables -I DOCKERWALL-ALLOW -s %s -m set --match-set %s dst -j ACCEPT", srcIP, ipsetName)
		if err != nil {
			return err
		}
	}

	//IPTABLES DENY
	denyRuleFound, err2 := s.findRule("DOCKERWALL-DENY", ipsetName)
	if err2 != nil {
		return err2
	}
	if !denyRuleFound {
		logrus.Debugf("Iptables rule not found in chain DOCKERWALL-DENY for %s. Creating.", ipsetName)
		_, err := ExecShellf("iptables -I DOCKERWALL-DENY -s src -m set ! --match-set %s dst -j DROP", srcIP, ipsetName)
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *Waller) updateIpsetIps(ipsetName string, domainNames string) error {
	logrus.Debugf("Adding IPSET group %s domains %s", ipsetName, domainNames)

	_, err := ExecShellf("ipset list | grep %s", ipsetName)
	if err != nil {
		logrus.Debugf("IPSET group %s seems not to exist. Creating. err=%s", ipsetName, err)
		_, err := ExecShellf("ipset -N %s iphash", ipsetName)
		if err != nil {
			return err
		}
	}

	logrus.Debugf("Getting domain name IPs and adding to ipset %s", ipsetName)
	_, err = ExecShellf("dig A +short %s | xargs -L1 ipset -A %s", domainNames, ipsetName)
	if err != nil {
		return err
	}

	return nil
}

func (s *Waller) findRule(chain string, ruleSubstr string) (bool, error) {
	rules, err1 := ExecShellf("iptables -L %s", chain)
	if err1 != nil {
		return false, err1
	}
	rul, err2 := linesToArray(rules)
	if err2 != nil {
		return false, err2
	}

	for _, v := range rul {
		if strings.Contains(v, ruleSubstr) {
			return true, nil
		}
	}

	return false, nil
}

func (s *Waller) containerGwIPs() (map[string]string, error) {
	logrus.Debugf("Discovering container GW ips")
	containersGwIP := map[string]string{}
	netins, err := s.dockerClient.NetworkInspect(context.Background(), "docker_gwbridge", types.NetworkInspectOptions{})
	if err != nil {
		logrus.Errorf("Error while listing container instances. err=%s", err)
		return containersGwIP, err
	}
	for k, cont := range netins.Containers {
		containersGwIP[k] = cont.IPv4Address
	}
	return containersGwIP, nil
}

func (s *Waller) updateIptablesChains() error {
	_, err := ExecShell("iptables -L DOCKER-USER")
	if err != nil {
		return fmt.Errorf("Couldn't find DOCKER-USER chain. Check if Docker is installed in this host. err=%s", err)
	}

	//check existing rules
	allowChainFound := false
	denyChainFound := false
	rules, err1 := ExecShell("iptables -L DOCKER-USER")
	if err1 != nil {
		return err1
	}
	rul, err2 := linesToArray(rules)
	if err2 != nil {
		return err2
	}
	for _, v := range rul {
		if strings.Contains(v, "DOCKERWALL-ALLOW") {
			allowChainFound = true
		} else if strings.Contains(v, "DOCKERWALL-DENY") {
			denyChainFound = true
		}
	}

	if !allowChainFound {
		logrus.Debug("Jump to DOCKERWALL-ALLOW not found in chain DOCKER-USER. Creating it")
		_, err = ExecShell("iptables -N DOCKERWALL-ALLOW")
		if err != nil {
			logrus.Debugf("Ignoring error on chain creating (it may already exist). err=%s", err)
		}
		_, err = ExecShell("iptables -I DOCKER-USER -j DOCKERWALL-ALLOW")
		if err != nil {
			return err
		}
	}

	if !denyChainFound {
		logrus.Debug("Jump to DOCKERWALL-DENY not found in chain DOCKER-USER. Creating it")
		_, err = ExecShell("iptables -N DOCKERWALL-DENY")
		if err != nil {
			logrus.Debugf("Ignoring error on chain creating (it may already exist). err=%s", err)
		}
		_, err = ExecShell("iptables -I DOCKER-USER -j DOCKERWALL-DENY")
		if err != nil {
			return err
		}
		_, err = ExecShell("iptables -I DOCKER-USER -j DROP")
		if err != nil {
			return err
		}
	}

	return nil
}
