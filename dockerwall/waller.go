package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"regexp"

	"github.com/Sirupsen/logrus"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
)

//Waller Label based network filter constraints
type Waller struct {
	dockerClient       *client.Client
	useDefaultNetworks bool
	gatewayNetworks    []string
}

func (s *Waller) startup() error {
	logrus.Infof("Performing initial full filter updates for all current containers")

	err := s.initialize()
	if err != nil {
		return err
	}

	go s.processDockerEvents()

	for {
		containers, err := s.dockerClient.ContainerList(context.Background(), types.ContainerListOptions{})
		if err != nil {
			logrus.Errorf("Error listing containers. err=%s", err)

		} else {
			logrus.Debug("Updating filters and domain ips")
			for _, cont := range containers {
				cid := trunc(cont.ID, 18)
				err = s.updateContainerFilters(cont)
				if err != nil {
					logrus.Errorf("Error updating container filter. container=%s, err=%s", cid, err)
				}
			}

			logrus.Debug("Looking for orphaned ipset or iptables rules")
			err = s.removeOrphans(containers)
			if err != nil {
				logrus.Errorf("Error removing orphans. err=%s", err)
			}
		}
		time.Sleep(10000000 * time.Millisecond)
	}
}

func (s *Waller) initialize() error {
	logrus.Debugf("initializing...")
	//if no network was defined, use all bridge networks by default
	if s.useDefaultNetworks {
		logrus.Debugf("No docker networks were defined. Will use all 'bridge' networks on host")
		opts := types.NetworkListOptions{
			Filters: filters.NewArgs(filters.KeyValuePair{Key: "driver", Value: "bridge"}),
		}
		bnetworks, err := s.dockerClient.NetworkList(context.Background(), opts)
		if err != nil {
			return err
		}
		s.gatewayNetworks = make([]string, 0)
		for _, bn := range bnetworks {
			s.gatewayNetworks = append(s.gatewayNetworks, bn.Name)
		}
	}
	logrus.Debugf("Bridge networks that will be managed: %v", s.gatewayNetworks)

	err := s.updateIptablesChains()
	if err != nil {
		return fmt.Errorf("Error updating iptables basic chains, err=%s", err)
	}

	return nil
}

func (s *Waller) updateContainerFilters(container types.Container) error {
	logrus.Debug("updateContainerFilters()")
	cid := trunc(container.ID, 18)
	//OUTBOUND DOMAIN IPs
	outboundLabelValue := ""
	for k, v := range container.Labels {
		if k == "dockerwall.outbound" {
			outboundLabelValue = v
		}
	}

	logrus.Debugf("Verifying IPTABLES rules for container %s", cid)

	//CONTAINER GW IP
	gwIps, err := s.containerGwIPs()
	if err != nil {
		return err
	}
	srcIPs, exists := gwIps[cid]
	if !exists {
		return fmt.Errorf("Could not find gateway IP for %s. Ignoring it", cid)
	}
	ipregex, _ := regexp.Compile("([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})")
	for i, si := range srcIPs {
		srcIPs[i] = ipregex.FindString(si)
	}

	//IPSET GROUP UPDATE
	ipsetName := trunc(cid, 18)
	ipsetName = ipsetName + "-dst"
	s.updateIpsetIps(ipsetName, outboundLabelValue)

	for _, srcIP := range srcIPs {
		logrus.Debugf("Checking iptables rules for container src ip %s", srcIP)

		//IPTABLES ALLOW
		allowRuleFound, err1 := s.findRule("DOCKERWALL-ALLOW", ipsetName, srcIP)
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
		denyRuleFound, err2 := s.findRule("DOCKERWALL-DENY", ipsetName, srcIP)
		if err2 != nil {
			return err2
		}
		if !denyRuleFound {
			logrus.Debugf("Iptables rule not found in chain DOCKERWALL-DENY for %s. Creating.", ipsetName)
			_, err := ExecShellf("iptables -I DOCKERWALL-DENY -s %s -m set ! --match-set %s dst -j DROP", srcIP, ipsetName)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (s *Waller) updateIpsetIps(ipsetName string, domainNames string) error {
	logrus.Debugf("Adding domains %s to IPSET group %s", domainNames, ipsetName)

	_, err := ExecShellf("ipset list | grep %s", ipsetName)
	if err != nil {
		logrus.Debugf("IPSET group %s seems not to exist. Creating. err=%s", ipsetName, err)
		_, err := ExecShellf("ipset -N %s iphash", ipsetName)
		if err != nil {
			return err
		}
	}

	ipregex, _ := regexp.Compile("([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})")
	ips := ipregex.FindAllString(domainNames, -1)
	ipstr := ""
	for _, ip := range ips {
		ipstr = ipstr + ip + "\n"
	}

	if ipstr != "" {
		logrus.Debugf("Adding ip rules to ipset %s. ips=%s", ipsetName, ipstr)
		_, err = ExecShellf("echo -e \"%s\" | xargs -L1 ipset -A %s", ipstr, ipsetName)
		if err != nil {
			logrus.Debugf("Couldn't add ips to ipset group. err=%s", err)
		}
	}

	domainregex, _ := regexp.Compile("([a-zA-Z0-9-\\.]+)")
	domains := domainregex.FindAllString(domainNames, -1)
	domainsstr := ""
	for _, domain := range domains {
		domainsstr = domainsstr + domain + " "
	}

	if domainsstr != "" {
		logrus.Debugf("Getting domain name IPs and adding to ipset %s. domains=%s", ipsetName, domainsstr)
		_, err1 := ExecShellf("dig A +short %s | xargs -L1 ipset -A %s", domainsstr, ipsetName)
		if err1 != nil {
			logrus.Debugf("Couldn't add ips to ipset group %s. err=%s", ipsetName, err1)
		}
	}

	return nil
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

func (s *Waller) removeOrphanRules(chain string, currentContainers map[string][]string) error {
	logrus.Debugf("Retrieving iptables rules for %s", chain)
	rules, err1 := ExecShellf("iptables -L %s -v --line-number", chain)
	if err1 != nil {
		return err1
	}
	rul, err2 := linesToArray(rules)
	if err2 != nil {
		return err2
	}

	cidregex, _ := regexp.Compile("match-set ([0-9a-zA-Z]+)-dst dst")
	lineregex, _ := regexp.Compile("^([0-9]+)")

	//invert rules order so that we can remove rules without changing the line numbers
	rul = reverseArray(rul)

	for _, v := range rul {
		ss := cidregex.FindStringSubmatch(v)
		if len(ss) == 2 {
			cid := ss[1]
			logrus.Debugf("Found container %s in iptables rule %s", cid, chain)
			_, exists := currentContainers[cid]
			if !exists {
				logrus.Infof("Found iptables rule for %s, but it doesn't exist anymore. Removing. v=%s", cid, v)
				ls := lineregex.FindStringSubmatch(v)
				if len(ls) == 2 {
					line := ls[1]
					logrus.Debugf("Found orphan rule %s for container %s. Removing it.", line, cid)
					_, err4 := ExecShellf("iptables -D %s %s", chain, line)
					if err4 != nil {
						logrus.Debugf("Error removing rule on line %s for container %s. err=%s", line, cid, err4)
					} else {
						logrus.Debug("Rule removed successfully")
					}
				}
			} else {
				logrus.Debugf("Container %s is not orphan", cid)
			}
		}
	}
	return nil
}

func (s *Waller) findRule(chain string, ruleSubstr string, ruleSubstr2 string) (bool, error) {
	rules, err1 := ExecShellf("iptables -L %s", chain)
	if err1 != nil {
		return false, err1
	}
	rul, err2 := linesToArray(rules)
	if err2 != nil {
		return false, err2
	}

	for _, v := range rul {
		if strings.Contains(v, ruleSubstr) && strings.Contains(v, ruleSubstr2) {
			return true, nil
		}
	}

	return false, nil
}

func (s *Waller) containerGwIPs() (map[string][]string, error) {
	containersGwIP := map[string][]string{}
	for _, gwNetwork := range s.gatewayNetworks {
		// logrus.Debugf("Discovering container ips for network %s", gwNetwork)
		netins, err := s.dockerClient.NetworkInspect(context.Background(), gwNetwork, types.NetworkInspectOptions{})
		if err != nil {
			logrus.Errorf("Error while listing container instances attached to network %s. err=%s", gwNetwork, err)
			return containersGwIP, err
		}
		for k, cont := range netins.Containers {
			k = trunc(k, 18)
			if containersGwIP[k] == nil {
				containersGwIP[k] = make([]string, 0)
			}
			containersGwIP[k] = append(containersGwIP[k], cont.IPv4Address)
		}
	}
	return containersGwIP, nil
}

func (s *Waller) updateIptablesChains() error {
	_, err := ExecShell("iptables -L DOCKER-USER")
	if err != nil {
		return fmt.Errorf("Error querying DOCKER-USER Iptables chain. Check if both Iptables and Docker are installed on this host. err=%s", err)
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

	logrus.Debug("Updating/creating ipset group for gateway subnets")
	ipsetName := "managed-subnets"
	_, err = ExecShellf("ipset list | grep %s", ipsetName)
	if err != nil {
		logrus.Debugf("IPSET group %s seems not to exist. Creating. err=%s", ipsetName, err)
		_, err := ExecShellf("ipset -N %s iphash", ipsetName)
		if err != nil {
			return err
		}
	}
	// TODO-fazer uma regra de iptables para cada rede, pois o ipset com subnet abre cada IP
	ipsetNameTemp := "managed-subnets-TEMP"
	_, err = ExecShellf("ipset list | grep %s", ipsetNameTemp)
	if err != nil {
		logrus.Debugf("IPSET group %s seems not to exist. Creating. err=%s", ipsetNameTemp, err)
		_, err := ExecShellf("ipset -N %s iphash", ipsetNameTemp)
		if err != nil {
			return err
		}
	}
	for _, gwNetwork := range s.gatewayNetworks {
		netins, err := s.dockerClient.NetworkInspect(context.Background(), gwNetwork, types.NetworkInspectOptions{})
		if err != nil {
			logrus.Errorf("Error while listing container instances. network=%s. err=%s", gwNetwork, err)
			return fmt.Errorf("Could not inspect docker network %s", gwNetwork)
		}
		if len(netins.IPAM.Config) > 0 {
			bridgeNetworkSubnet := netins.IPAM.Config[0].Subnet
			_, err := ExecShellf("ipset -A %s %s", ipsetNameTemp, bridgeNetworkSubnet)
			if err != nil {
				logrus.Debugf("Error adding gw network subnet to ipset. Maybe it already exists. err=%s", err)
			}
		} else {
			return fmt.Errorf("Could not find subnet configuration for docker network %s", gwNetwork)
		}
	}
	logrus.Debug("Commiting ipset group used for gw network subnets")
	_, err = ExecShellf("ipset swap %s %s", ipsetNameTemp, ipsetName)
	if err != nil {
		logrus.Warnf("Error updating ipset used for network subnets. err=%s", err)
	}

	if !denyChainFound {
		logrus.Debugf("Adding default DROP policy for packets from gateway networks")
		_, err = ExecShellf("iptables -I DOCKER-USER -m set --match-set %s src -j DROP", ipsetName)
		if err != nil {
			return err
		}

		logrus.Debug("DOCKERWALL-DENY jump not found in chain DOCKER-USER. Creating it")
		_, err = ExecShell("iptables -N DOCKERWALL-DENY")
		if err != nil {
			logrus.Debugf("Ignoring error on chain creation (it may already exist). err=%s", err)
		}
		_, err = ExecShell("iptables -I DOCKER-USER -j DOCKERWALL-DENY")
		if err != nil {
			return err
		}
	}

	if !allowChainFound {
		logrus.Debug("DOCKERWALL-ALLOW jump not found in chain DOCKER-USER. Creating it")
		_, err = ExecShell("iptables -N DOCKERWALL-ALLOW")
		if err != nil {
			logrus.Debugf("Ignoring error on chain creating (it may already exist). err=%s", err)
		}
		_, err = ExecShell("iptables -I DOCKER-USER -j DOCKERWALL-ALLOW")
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *Waller) processDockerEvents() {
	for {
		logrus.Info("Starting to listen to docker events")
		opts := types.EventsOptions{
			Filters: filters.NewArgs(
				filters.KeyValuePair{Key: "type", Value: "container"},
				filters.KeyValuePair{Key: "type", Value: "network"},
			),
		}
		chanMessages, chanError := s.dockerClient.Events(context.Background(), opts)
		go s.processMessages(chanMessages)
		err := <-chanError
		logrus.Warnf("Found error on Docker events listen. restarting. err=%s", err)
	}
}

func (s *Waller) processMessages(chanMessages <-chan events.Message) {
	for message := range chanMessages {
		logrus.Debugf("Received Docker event message %v", message)
		useful := false
		if message.Type == "container" {
			if message.Action == "start" || message.Action == "stop" || message.Action == "die" {
				useful = true
				opts := types.ContainerListOptions{
					Filters: filters.NewArgs(
						filters.KeyValuePair{Key: "id", Value: message.Actor.ID},
					),
				}
				containers, err := s.dockerClient.ContainerList(context.Background(), opts)
				if err != nil {
					logrus.Debugf("Error listing containers. err=%s", err)
					continue
				}
				if len(containers) == 1 {
					s.updateContainerFilters(containers[0])
				} else {
					logrus.Warnf("Container listing should return one container for ID %s", message.Actor.ID)
				}
			}

		} else if message.Type == "network" {
			if message.Action == "create" || message.Action == "destroy" {
				useful = true
				s.initialize()
			}
		}

		if useful {
			logrus.Debug("Looking for orphaned ipset or iptables rules")
			allContainers, err := s.dockerClient.ContainerList(context.Background(), types.ContainerListOptions{})
			if err != nil {
				logrus.Errorf("Error removing orphans. err=%s", err)
			}
			err = s.removeOrphans(allContainers)
			if err != nil {
				logrus.Errorf("Error removing orphans. err=%s", err)
			}
		}
	}
}
