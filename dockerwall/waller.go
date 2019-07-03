package dockerwall

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"regexp"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	nflog "github.com/florianl/go-nflog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

//Waller Label based network filter constraints
type Waller struct {
	DockerClient       *client.Client
	UseDefaultNetworks bool
	GatewayNetworks    []string
	DefaultOutbound    string
	DryRun             bool
	SkipNetworks       []string
	CurrentMetrics     string
	MetricsDropHosts   map[string]map[string]int
	M                  *sync.Mutex
}

func (s *Waller) Startup() error {
	logrus.Infof("Performing startup operations")

	s.MetricsDropHosts = make(map[string]map[string]int)

	err := s.updateGatewayNetworks()
	if err != nil {
		return err
	}

	go s.sanitizer()
	go s.dockerEvents()
	go s.metrics()
	go s.nflog()

	router := mux.NewRouter()
	router.HandleFunc("/metrics", s.MetricsHandler).Methods("GET")
	err = http.ListenAndServe("0.0.0.0:50000", router)
	if err != nil {
		logrus.Errorf("Error while listening requests: %s", err)
		os.Exit(1)
	}

	return nil
}

func (s *Waller) sanitizer() {
	logrus.Debugf("Starting sanitizer")
	for {
		s.M.Lock()

		logrus.Debugf("Refreshing basic network and iptables rules")
		s.updateGatewayNetworks()

		containers, err := s.refreshAllContainerRules()
		if err != nil {
			logrus.Errorf("Error refreshing container rules. err=%s", err)
		} else {
			logrus.Debug("Looking for orphaned ipset or iptables rules")
			err = s.removeOrphans(containers)
			if err != nil {
				logrus.Errorf("Error removing orphans. err=%s", err)
			}
			logrus.Infof("Iptables orphan rules sanitizer run")
		}
		s.M.Unlock()
		time.Sleep(300000 * time.Millisecond)
	}
}

func (s *Waller) dockerEvents() {
	for {
		logrus.Info("Starting to listen to docker events")
		opts := types.EventsOptions{
			Filters: filters.NewArgs(
				filters.KeyValuePair{Key: "type", Value: "container"},
				filters.KeyValuePair{Key: "type", Value: "network"},
			),
		}
		chanMessages, chanError := s.DockerClient.Events(context.Background(), opts)
		go s.processMessages(chanMessages)
		err := <-chanError
		logrus.Warnf("Found error on Docker events listen. restarting. err=%s", err)
	}
}

// MetricsHandler return current metrics
func (s *Waller) MetricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(s.CurrentMetrics))
}

func (s *Waller) metrics() {
	first := true
	for {
		if !first {
			time.Sleep(3000 * time.Millisecond)
		}
		first = false

		s.M.Lock()

		metricsAllow, err := s.chainMetrics("DOCKERWALL-ALLOW")
		if err != nil {
			logrus.Warnf("Error generating metrics (ALLOW). err=%s", err)
			continue
		}
		metricsDeny, err := s.chainMetrics("DOCKERWALL-DENY")
		if err != nil {
			logrus.Warnf("Error generating metrics (DENY). err=%s", err)
			continue
		}

		//dropped hosts metrics
		metricsDrop := ""
		containers, err := s.containerList()
		for containerid, hostsCounter := range s.MetricsDropHosts {
			containerName := containerid
			if len(containers[containerid].Names) > 0 {
				containerName = strings.Replace(containers[containerid].Names[0], "/", "", 1)
			}
			imageName := containers[containerid].Image
			for destIPPortProto, counter := range hostsCounter {
				dest := strings.Split(destIPPortProto, ":")
				metricName := "dockerwall_dropped_packets"
				m := "#HELP " + metricName + " Number of packets denied by Dockerwall\n"
				m = m + "#TYPE " + metricName + " counter\n"
				m = m + fmt.Sprintf("%s{id=\"%s\",name=\"%s\",image=\"%s\",destination=\"%s\",port=\"%s\",protocol=\"%s\"} %d\n\n", metricName, containerid, containerName, imageName, dest[0], dest[1], dest[2], counter)
				metricsDrop = metricsDrop + m
			}
		}

		s.CurrentMetrics = metricsAllow + metricsDeny + metricsDrop
		s.M.Unlock()
	}
}

//returns int[packet_count, bytes_total] string[containerId, effect]
func (s *Waller) chainMetrics(chainName string) (string, error) {
	linesStr, err := ExecShellf("iptables -L %s -v -x", chainName)
	if err != nil {
		return "", err
	}
	lines, err := linesToArray(linesStr)
	if err != nil {
		return "", err
	}

	containers, err := s.containerList()

	metrics := ""
	spaceregex := regexp.MustCompile(`\s+`)
	for _, line := range lines {
		if line == "\n" {
			continue
		}

		containeridregex := regexp.MustCompile("match-set ([-0-9a-z]+)-dst dst")

		if containeridregex.MatchString(line) {
			mcid := containeridregex.FindStringSubmatch(line)
			if len(mcid) != 2 {
				logrus.Warnf("Could not find container id in line %s", line)
				continue
			}
			containerid := mcid[1]
			containerName := containerid
			if len(containers[containerid].Names) > 0 {
				containerName = strings.Replace(containers[containerid].Names[0], "/", "", 1)
			}
			imageName := containers[containerid].Image

			line = spaceregex.ReplaceAllString(line, " ")
			fields := strings.Split(line, " ")
			action := strings.ToLower(fields[3])

			if action != "drop" && action != "accept" {
				continue
			}

			metricName := "dockerwall_container_packets"
			m := "#HELP " + metricName + " Number of packets originated by a container\n"
			m = m + "#TYPE " + metricName + " counter\n"
			m = m + fmt.Sprintf("%s{id=\"%s\",name=\"%s\",image=\"%s\",action=\"%s\"} %s\n\n", metricName, containerid, containerName, imageName, action, fields[1])

			metricName = "dockerwall_container_bytes"
			m = m + "#HELP " + metricName + " Total bytes originated by a container\n"
			m = m + "#TYPE " + metricName + " counter\n"
			m = m + fmt.Sprintf("%s{id=\"%s\",name=\"%s\",image=\"%s\",action=\"%s\"} %s\n\n", metricName, containerid, containerName, imageName, action, fields[2])

			metrics = metrics + m
		}
	}
	// logrus.Debugf("Current metrics: \n%s", metrics)
	return metrics, nil
}

func (s *Waller) nflog() {
	logrus.Debugf("Starting nflog packet listener")

	config := nflog.Config{
		Group:    32,
		Copymode: nflog.NfUlnlCopyPacket,
	}

	nf, err := nflog.Open(&config)
	if err != nil {
		logrus.Errorf("Could not open nflog socket: %s", err)
		return
	}
	defer nf.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fn := func(m nflog.Msg) int {
		// logrus.Infof("%s %v\n", m[nflog.AttrPrefix], m[nflog.AttrPayload])
		containerID := m[nflog.AttrPrefix].(string)
		payload := m[nflog.AttrPayload].([]byte)
		packet := gopacket.NewPacket(payload, layers.LayerTypeIPv4, gopacket.Default)
		ip4Layer := packet.Layer(layers.LayerTypeIPv4)

		if ip4Layer != nil {
			ipv4, _ := ip4Layer.(*layers.IPv4)
			// logrus.Debugf("DROP src host %d to dst host %d", ipv4.SrcIP, ipv4.DstIP)

			port := "0"
			protocol := "-"
			for _, layer := range packet.Layers() {
				if layer.LayerType() == layers.LayerTypeTCP {
					tcpLayer := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
					protocol = "tcp"
					port = fmt.Sprintf("%d", tcpLayer.DstPort)
					break
				} else if layer.LayerType() == layers.LayerTypeUDP {
					udpLayer := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
					protocol = "udp"
					port = fmt.Sprintf("%d", udpLayer.DstPort)
					break
				}
			}

			destinationIP := fmt.Sprintf("%d.%d.%d.%d:%s:%s", ipv4.DstIP[0], ipv4.DstIP[1], ipv4.DstIP[2], ipv4.DstIP[3], port, protocol)

			dropHosts, exists := s.MetricsDropHosts[containerID]
			if !exists {
				s.MetricsDropHosts[containerID] = make(map[string]int)
				dropHosts = s.MetricsDropHosts[containerID]
			}

			_, exists = dropHosts[destinationIP]
			if !exists {
				dropHosts[destinationIP] = 0
			}
			dropHosts[destinationIP] = dropHosts[destinationIP] + 1

		} else {
			logrus.Warnf("Could not get IPv4 Layer from NFLOG message")
		}
		return 0
	}

	err = nf.Register(ctx, fn)
	if err != nil {
		fmt.Println(err)
		return
	}

	<-ctx.Done()
	logrus.Warnf("NFLog reader exited")
}

func (s *Waller) processMessages(chanMessages <-chan events.Message) {
	for message := range chanMessages {
		s.M.Lock()
		logrus.Debugf("Received Docker event message %v", message)
		if message.Type == "container" {
			//IPSET GROUP UPDATE
			ipsetName := trunc(message.Actor.ID, 18)
			ipsetName = ipsetName + "-dst"
			if message.Action == "start" {

				opts := types.ContainerListOptions{
					Filters: filters.NewArgs(
						filters.KeyValuePair{Key: "id", Value: message.Actor.ID},
					),
				}
				containers, err := s.DockerClient.ContainerList(context.Background(), opts)
				if err != nil {
					logrus.Debugf("Error listing containers. err=%s", err)
					continue
				}
				if len(containers) == 1 {
					container := containers[0]

					_, err = ExecShellf("ipset list | grep %s", ipsetName)
					if err != nil {
						logrus.Debugf("First time seeing this container. Preparing iptables and ipset outbound ips")
						s.updateContainerFilters(container)
					} else {
						logrus.Debugf("Container already known. Updating ipset outbound ips")
						s.updateIpsetIps(ipsetName, container)
					}
					logrus.Infof("Ipset group %s updated", ipsetName)

				} else {
					logrus.Warnf("Container %s not found", message.Actor.ID)
				}

			} else if message.Action == "stop" || message.Action == "die" {
				logrus.Debugf("Keeping iptables rules, but clearing ipset group ips to avoid outbound colision while remove orphans task is not run")
				_, err := ExecShellf("ipset flush %s", ipsetName)
				if err != nil {
					logrus.Warnf("Error clearing ipset group %s", ipsetName)
				}
				logrus.Infof("Ipset group %s cleared", ipsetName)
			}

		} else if message.Type == "network" {
			if message.Action == "create" || message.Action == "destroy" {
				s.updateGatewayNetworks()
				logrus.Info("Gateway network rules updated")
			}
		}
		s.M.Unlock()
	}
}

func (s *Waller) updateGatewayNetworks() error {
	logrus.Debugf("updateGatewayNetworks()")
	//if no network was defined, use all bridge networks by default
	if s.UseDefaultNetworks {
		logrus.Debugf("No docker networks were defined. Will use all 'bridge' networks on host")
		opts := types.NetworkListOptions{
			Filters: filters.NewArgs(filters.KeyValuePair{Key: "driver", Value: "bridge"}),
		}
		bnetworks, err := s.DockerClient.NetworkList(context.Background(), opts)
		if err != nil {
			return err
		}
		s.GatewayNetworks = make([]string, 0)
		for _, bn := range bnetworks {
			if !contains(s.SkipNetworks, bn.Name) {
				s.GatewayNetworks = append(s.GatewayNetworks, bn.Name)
			} else {
				logrus.Debugf("Network '%s' won't be managed", bn.Name)
			}
		}
	}
	logrus.Debugf("Bridge networks that will be managed: %v", s.GatewayNetworks)

	err := s.updateIptablesChains()
	if err != nil {
		return fmt.Errorf("Error updating iptables basic chains, err=%s", err)
	}

	return nil
}

func (s *Waller) updateContainerFilters(container types.Container) error {
	logrus.Debug("updateContainerFilters()")
	cid := trunc(container.ID, 18)

	logrus.Debugf("Verifying IPTABLES rules for container %s", cid)

	//CONTAINER GW IP
	gwIps, _, err := s.containerGwIPs()
	if err != nil {
		return err
	}
	srcIPs, exists := gwIps[cid]
	if !exists {
		return fmt.Errorf("Could not find gateway IP for %s", cid)
	}
	ipregex, _ := regexp.Compile("([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})")
	for i, si := range srcIPs {
		srcIPs[i] = ipregex.FindString(si)
	}

	//IPSET GROUP UPDATE
	containerID := trunc(cid, 18)
	ipsetName := containerID + "-dst"
	s.updateIpsetIps(ipsetName, container)

	//IPTABLES CHAINS
	for _, srcIP := range srcIPs {
		logrus.Debugf("Checking iptables rules for container src ip %s", srcIP)

		//IPTABLES ALLOW
		allowRuleFound, err1 := s.findRule("DOCKERWALL-ALLOW", ipsetName, srcIP, "")
		if err1 != nil {
			return err1
		}
		if !allowRuleFound {
			logrus.Debugf("Iptables rule not found in chain DOCKERWALL-ALLOW for %s. Creating.", ipsetName)
			_, err := ExecShellf("iptables -I DOCKERWALL-ALLOW -s %s -m set --match-set %s dst -j ACCEPT", srcIP, ipsetName)
			if err != nil {
				return err
			}
			logrus.Infof("DOCKERWALL-ALLOW rule for %s created succesfully", ipsetName)
		}

		//IPTABLES DENY
		jump := "DROP"
		notJump := "ACCEPT"
		if s.DryRun {
			jump = "ACCEPT"
			notJump = "DROP"
		}

		denyRuleFound, err2 := s.findRule("DOCKERWALL-DENY", ipsetName, srcIP, jump)
		if err2 != nil {
			return err2
		}
		if !denyRuleFound {
			logrus.Debugf("Iptables rule not found in chain DOCKERWALL-DENY for %s %s. Creating.", ipsetName, jump)

			_, err := ExecShellf("iptables -I DOCKERWALL-DENY -s %s -m set ! --match-set %s dst -j %s", srcIP, ipsetName, jump)
			if err != nil {
				return err
			}
			logrus.Infof("DOCKERWALL-DENY %s rule for %s created succesfully", jump, ipsetName)

			//-m limit --limit 1/second
			_, err = ExecShellf("iptables -I DOCKERWALL-DENY -s %s -m set ! --match-set %s dst -j NFLOG --nflog-prefix \"%s\" --nflog-group 32", srcIP, ipsetName, containerID)
			if err != nil {
				return err
			}
			logrus.Infof("DOCKERWALL-DENY LOG rule for %s created succesfully", ipsetName)
		}

		//remove inconsistent rule (probably due to previous dry run)
		wrongDenyRuleFound, err3 := s.findRule("DOCKERWALL-DENY", ipsetName, srcIP, notJump)
		if err3 != nil {
			return err3
		}
		if wrongDenyRuleFound {
			logrus.Debugf("Clearing rule from DOCKERWALL-DENY chain. srcIP=%s. ipsetName=%s. jump=%s", srcIP, ipsetName, notJump)
			_, err := ExecShellf("iptables -D DOCKERWALL-DENY -s %s -m set ! --match-set %s dst -j %s", srcIP, ipsetName, notJump)
			if err != nil {
				return err
			}
			logrus.Infof("DOCKERWALL-DENY %s rule for %s removed succesfully", notJump, ipsetName)
		}

	}

	return nil
}

func (s *Waller) updateIpsetIps(ipsetName string, container types.Container) error {
	//OUTBOUND DOMAIN IPs
	domainNames := s.DefaultOutbound
	if !strings.Contains(domainNames, "!_dns_") && !strings.Contains(domainNames, "_dns_") {
		domainNames = domainNames + ",_dns_"
	}
	for k, v := range container.Labels {
		if k == "dockerwall.outbound" {
			domainNames = domainNames + "," + v
			break
		}
	}

	logrus.Debugf("Adding domains %s to IPSET group %s", domainNames, ipsetName)

	_, err := ExecShellf("ipset list | grep %s", ipsetName)
	if err != nil {
		logrus.Debugf("IPSET group %s seems not to exist. Creating. err=%s", ipsetName, err)
		_, err := ExecShellf("ipset -N %s iphash", ipsetName)
		if err != nil {
			return err
		}
	}

	//if domain has '_dns_', lookup dns server IP
	if strings.Contains(domainNames, "_dns_") {
		nsoutput, err := ExecShellf("dig 8.8.8.8")
		if err != nil {
			logrus.Debugf("Couldn't discover DNS server ip. err=%s", err)
		} else {
			nsserverregex := regexp.MustCompile("\\(([0-9\\.]{7,15})\\)")
			nsserver := nsserverregex.FindStringSubmatch(nsoutput)
			if len(nsserver) > 1 {
				domainNames = domainNames + "," + nsserver[1]
			}
		}
	}

	//add plain ip references
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

	//add domain name references
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
	currentContainers, _, err := s.containerGwIPs()
	if err != nil {
		return err
	}

	//REMOVE IPTABLES RULES
	ocid1, err1 := s.removeOrphanRules("DOCKERWALL-ALLOW", currentContainers)
	if err1 != nil {
		return err1
	}
	ocid2, err2 := s.removeOrphanRules("DOCKERWALL-DENY", currentContainers)
	if err2 != nil {
		return err2
	}

	//REMOVE IPSET GROUPS, BECAUSE THEY HAVE NO DEPENDENCIES NOW
	orphanCids := append(ocid1, ocid2...)
	orphanCids = unique(orphanCids)
	for _, cid := range orphanCids {
		ipsetName := cid + "-dst"
		logrus.Debugf("Removing ipset group %s", ipsetName)
		_, err5 := ExecShellf("ipset destroy %s", ipsetName)
		if err5 != nil {
			return fmt.Errorf("Error removing ipset group %s. err=%s", ipsetName, err5)
		} else {
			logrus.Infof("Ipset group %s removed successfully", ipsetName)
		}
	}

	return nil
}

//returns list of detected orphan rules container ids in iptables
func (s *Waller) removeOrphanRules(chain string, currentContainers map[string][]string) ([]string, error) {
	logrus.Debugf("Retrieving iptables rules for %s", chain)
	rules, err1 := ExecShellf("iptables -L %s -v --line-number", chain)
	if err1 != nil {
		return nil, err1
	}
	rul, err2 := linesToArray(rules)
	if err2 != nil {
		return nil, err2
	}

	cidregex, _ := regexp.Compile("match-set ([0-9a-zA-Z]+)-dst dst")
	lineregex, _ := regexp.Compile("^([0-9]+)")

	//invert rules order so that we can remove rules without changing the line numbers
	rul = reverseArray(rul)

	ocids := make([]string, 0)
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

					//IPTABLES RULES
					logrus.Debugf("Found orphan rule %s for container %s. Removing it.", line, cid)
					_, err4 := ExecShellf("iptables -D %s %s", chain, line)
					if err4 != nil {
						return nil, fmt.Errorf("Error removing rule on line %s for container %s. err=%s", line, cid, err4)
					} else {
						ocids = append(ocids, cid)
						logrus.Infof("Rule for %s removed successfully", cid)
					}
				}
			} else {
				logrus.Debugf("Container %s is not orphan", cid)
			}
		}
	}
	return ocids, nil
}

func (s *Waller) findRule(chain string, ruleSubstr string, ruleSubstr2 string, ruleSubstr3 string) (bool, error) {
	rules, err1 := ExecShellf("iptables -L %s", chain)
	if err1 != nil {
		return false, err1
	}
	rul, err2 := linesToArray(rules)
	if err2 != nil {
		return false, err2
	}

	for _, v := range rul {
		if strings.Contains(v, ruleSubstr) && strings.Contains(v, ruleSubstr2) && strings.Contains(v, ruleSubstr3) {
			return true, nil
		}
	}

	return false, nil
}

func (s *Waller) containerGwIPs() (map[string][]string, map[string]string, error) {
	containersGwIP := map[string][]string{}
	containerNames := map[string]string{}
	for _, gwNetwork := range s.GatewayNetworks {
		// logrus.Debugf("Discovering container ips for network %s", gwNetwork)
		netins, err := s.DockerClient.NetworkInspect(context.Background(), gwNetwork, types.NetworkInspectOptions{})
		if err != nil {
			logrus.Errorf("Error while listing container instances attached to network %s. err=%s", gwNetwork, err)
			return containersGwIP, containerNames, err
		}
		for k, cont := range netins.Containers {
			k = trunc(k, 18)
			if containersGwIP[k] == nil {
				containersGwIP[k] = make([]string, 0)
			}
			containersGwIP[k] = append(containersGwIP[k], cont.IPv4Address)
			containerNames[k] = cont.Name
		}
	}
	return containersGwIP, containerNames, nil
}

func (s *Waller) containerList() (map[string]types.Container, error) {
	containers := make(map[string]types.Container)
	contlist, err := s.DockerClient.ContainerList(context.Background(), types.ContainerListOptions{})
	if err != nil {
		logrus.Errorf("Error while listing container instances. err=%s", err)
		return containers, err
	}
	for _, cont := range contlist {
		id := trunc(cont.ID, 18)
		containers[id] = cont
	}
	return containers, nil
}

func (s *Waller) updateIptablesChains() error {
	logrus.Debugf("updateIptablesChains()")
	if s.DryRun {
		logrus.Infof("dry-run detected")
	}

	previousWasDryRun, err := s.findRule("DOCKERWALL-DENY", "ACCEPT", "ACCEPT", "")
	if err != nil {
		previousWasDryRun = true
	}

	if previousWasDryRun {
		if !s.DryRun {
			logrus.Debugf("Previous was dry-run and now it's not dry-run. Refresh container rules")
			s.refreshAllContainerRules()
		}
	} else {
		if s.DryRun {
			logrus.Debugf("Previous was not dry-run and now it's dry-run. Refresh container rules")
			s.refreshAllContainerRules()
		}
	}

	//check existing rules
	rules, err1 := ExecShell("iptables -L DOCKER-USER")
	if err1 != nil {
		return fmt.Errorf("Error querying DOCKER-USER Iptables chain. Check if both Iptables and Docker are installed on this host. err=%s", err1)
	}
	rul, err2 := linesToArray(rules)
	if err2 != nil {
		return err2
	}
	previousUserRulesCount := len(rul) - 2

	logrus.Debug("Updating/creating ipset group for gateway subnets")
	ipsetName := "managed-subnets"
	_, err = ExecShellf("ipset list | grep %s", ipsetName)
	if err != nil {
		logrus.Debugf("IPSET group %s seems not to exist. Creating. err=%s", ipsetName, err)
		_, err := ExecShellf("ipset -N %s nethash", ipsetName)
		if err != nil {
			return err
		}
	}

	ipsetNameTemp := "managed-subnets-TEMP"
	_, err = ExecShellf("ipset list | grep %s", ipsetNameTemp)
	if err != nil {
		logrus.Debugf("IPSET group %s seems not to exist. Creating. err=%s", ipsetNameTemp, err)
		_, err := ExecShellf("ipset -N %s nethash", ipsetNameTemp)
		if err != nil {
			return err
		}
	}

	for _, gwNetwork := range s.GatewayNetworks {
		netins, err := s.DockerClient.NetworkInspect(context.Background(), gwNetwork, types.NetworkInspectOptions{})
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
		return fmt.Errorf("Error updating ipset used for network subnets. err=%s", err)
	}
	logrus.Info("ipset groups for managed networks created successfully")

	logrus.Debug("Creating DOCKERWALL-DENY and DOCKERWALL-ALLOW chains")
	_, err = ExecShell("iptables -N DOCKERWALL-ALLOW")
	if err != nil {
		logrus.Debugf("Ignoring error on chain creating (it may already exist). err=%s", err)
	}
	_, err = ExecShell("iptables -N DOCKERWALL-DENY")
	if err != nil {
		logrus.Debugf("Ignoring error on chain creation (it may already exist). err=%s", err)
	}

	logrus.Debugf("Adding default DROP policy for packets from gateway networks")
	_, err = ExecShellf("iptables -I DOCKER-USER -m set --match-set %s src -j DROP", ipsetName)
	if err != nil {
		return err
	}

	if s.DryRun {
		logrus.Debug("Adding DOCKERWALL-ALLOW jump to chain DOCKER-USER")
		_, err = ExecShell("iptables -I DOCKER-USER -m set --match-set managed-subnets src -j DOCKERWALL-ALLOW")
		if err != nil {
			return err
		}
		logrus.Debug("Adding DOCKERWALL-DENY jump to chain DOCKER-USER")
		_, err = ExecShell("iptables -I DOCKER-USER -m set --match-set managed-subnets src -j DOCKERWALL-DENY")
		if err != nil {
			return err
		}

	} else {
		logrus.Debug("Adding DOCKERWALL-DENY jump to chain DOCKER-USER")
		_, err = ExecShell("iptables -I DOCKER-USER -m set --match-set managed-subnets src -j DOCKERWALL-DENY")
		if err != nil {
			return err
		}

		logrus.Debug("Adding DOCKERWALL-ALLOW jump to chain DOCKER-USER")
		_, err = ExecShell("iptables -I DOCKER-USER -m set --match-set managed-subnets src -j DOCKERWALL-ALLOW")
		if err != nil {
			return err
		}
	}

	rules, err1 = ExecShell("iptables -L DOCKERWALL-ALLOW")
	if err1 != nil {
		return err1
	}
	if !strings.Contains(rules, "ACCEPT     all  --  anywhere             anywhere             state ESTABLISHED match-set managed-subnets src") {
		_, err = ExecShell("iptables -I DOCKERWALL-ALLOW -m state --state ESTABLISHED -m set --match-set managed-subnets src -j ACCEPT")
		if err != nil {
			return err
		}
	}

	logrus.Debugf("Removing previous rules from DOCKER-USER chain")
	for i := previousUserRulesCount; i > 0; i-- {
		_, err = ExecShellf("iptables -D DOCKER-USER %d", i+3)
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *Waller) refreshAllContainerRules() ([]types.Container, error) {
	logrus.Debugf("Refreshing container specific rules")
	containers, err := s.DockerClient.ContainerList(context.Background(), types.ContainerListOptions{})
	if err != nil {
		logrus.Errorf("Error listing containers. err=%s", err)
		return []types.Container{}, err
	}

	logrus.Debug("Updating filters and domain ips")
	for _, cont := range containers {
		cid := trunc(cont.ID, 18)
		err = s.updateContainerFilters(cont)
		if err != nil {
			logrus.Warnf("Error updating container filter. container=%s, err=%s", cid, err)
		}
	}
	return containers, nil
}
