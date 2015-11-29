/*
Copyright 2015 Jan Broer All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"fmt"
	"net"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/janeczku/go-redwall/iptables"
)

// create user chains and jump rules in INPUT and FORWARD chain
func initChains() error {

	// create user chains
	_, err := iptables.NewChain("redwall-main", iptables.Filter, false)
	if  err != nil {
		return err
	}

	_, err = iptables.NewChain("redwall-whitelist", iptables.Filter, false)
	if  err != nil {
		return err
	}

	_, err = iptables.NewChain("redwall-services", iptables.Filter, false)
	if  err != nil {
		return err
	}

	_, err = iptables.NewChain("redwall-sshscan", iptables.Filter, false)
	if  err != nil {
		return err
	}

	// set default policy to ACCEPT
	if _, err = iptables.Raw("-P", "INPUT", "ACCEPT"); err != nil {
		return err
	}

	if _, err = iptables.Raw("-P", "FORWARD", "ACCEPT"); err != nil {
		return err
	}

	// flush INPUT chain
	if _, err = iptables.Raw("-F", "INPUT"); err != nil {
		return err
	}

	log.Debugf("created redwall user chains")
	return nil
}

// Create the boilerplate rules in redwall-main
func initDefaultRules() error {
	var chain string = "redwall-main"

	// flush existing rules in the chain
	if _, err := iptables.Raw("-F", chain); err != nil {
		return fmt.Errorf("flushing iptables chain %q failed: %v", chain, err)
	}
	log.Debugf("flushed iptables chain %q", chain)

	// allow established/related conns
	// iptables -A redwall-main -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
	if _, err := iptables.Raw("-A", chain, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"); err != nil {
		return err
	}

	// block null packets
	// iptables -A redwall-main -p tcp --tcp-flags ALL NONE -j DROP
	if _, err := iptables.Raw("-A", chain, "-p", "tcp", "--tcp-flags", "ALL", "NONE", "-j", "DROP"); err != nil {
		return err
	}

	// block XMAS packets
	// iptables -A redwall-main -p tcp --tcp-flags ALL ALL -j DROP
	if _, err := iptables.Raw("-A", chain, "-p", "tcp", "--tcp-flags", "ALL", "ALL", "-j", "DROP"); err != nil {
		return err
	}

	// block invalid packets
	// iptables -A redwall-main -m conntrack --ctstate INVALID -j DROP
	if _, err := iptables.Raw("-A", chain, "-m", "conntrack", "--ctstate", "INVALID", "-j", "DROP"); err != nil {
		return err
	}

	// block remote packets claiming to be from a loopback address.
	// iptables -A redwall-main -s 127.0.0.0/8 -j DROP
	if _, err := iptables.Raw("-A", chain, "-s", "127.0.0.0/8", "-j", "DROP"); err != nil {
		return err
	}

	// allow ICMP ping
	// iptables -A redwall-main -p icmp --icmp-type 8 -m conntrack --ctstate NEW -j ACCEPT
	if _, err := iptables.Raw("-A", chain, "-p", "icmp", "--icmp-type", "8", "-m", "conntrack", "--ctstate", "NEW", "-j", "ACCEPT"); err != nil {
		return err
	}

	// continue processing in redwall-whitelist
	if _, err := iptables.Raw("-A", chain, "-j", "redwall-whitelist"); err != nil {
		return err
	}

	// continue processing in redwall-services
	if _, err := iptables.Raw("-A", chain, "-j", "redwall-services"); err != nil {
		return err
	}

	// Jump to SSH chain
	// iptables -A redwall-main -p tcp --dport 22 --ctstate NEW -j ACCEPT
	if _, err := iptables.Raw("-A", chain, "-p", "tcp", "--dport", "22", "-m", "conntrack", "--ctstate", "NEW", "-j", "redwall-sshscan"); err != nil {
		return err
	}

	// drop all other incoming packets on iface
	if _, err := iptables.Raw("-A", chain, "-j", "DROP"); err != nil {
		return err
	}

	log.Debugf("created boilerplate rules in redwall-main")
	return nil
}

// Setup SSH chain rules
func initSSHRules() error {
	var chain string = "redwall-sshscan"

	// flush existing rules in the chain
	if _, err := iptables.Raw("-F", chain); err != nil {
		return fmt.Errorf("flushing iptables chain %q failed: %v", chain, err)
	}
	log.Debugf("flushed iptables chain %q", chain)

	if filterSSH {
		_, err := iptables.Raw("-A", chain, "-m", "recent", "--set", "--name", "SSH")
		if err != nil {
			return err
		}

		_, err = iptables.Raw("-A", chain, "-m", "recent", "--update", "--seconds", "60", "--hitcount", "5", "--name", "SSH", "--rttl", "-m", "limit", "--limit", "1/m", "-j", "LOG",
			"--log-level", "5", "--log-prefix", "Detected fast SSH-Bruteforce ")
		if err != nil {
			return err
		}

		_, err = iptables.Raw("-A", chain, "-m", "recent", "--update", "--seconds", "60", "--hitcount", "5", "--name", "SSH", "--rttl", "-j", "REJECT",
			"--reject-with", "icmp-port-unreachable")
		if err != nil {
			return err
		}

		_, err = iptables.Raw("-A", chain, "-m", "recent", "--rcheck", "--seconds", "3600", "--hitcount", "10", "--name", "SSH", "--rttl", "-m", "limit", "--limit", "1/h", "-j", "LOG",
			"--log-level", "5", "--log-prefix", "Detected slow SSH-Bruteforce ")
		if err != nil {
			return err
		}

		_, err = iptables.Raw("-A", chain, "-m", "recent", "--rcheck", "--seconds", "3600", "--hitcount", "10", "--name", "SSH", "--rttl", "-j", "DROP")
		if err != nil {
			return err
		}
		log.Debugf("created SSH bruteforce attack mitigation rules")
	}

	if allowSSH {
		if _, err := iptables.Raw("-A", chain, "-j", "ACCEPT"); err != nil {
			return err
		}
		log.Debugf("created rule to allow SSH connections")
	}

	return nil
}

// Activate firewall only when all other commands succeeded
func activateFirewall() error {
	// create INPUT chain jump rule
	rule := []string{
		"-i", iface,
		"-j", "redwall-main"}
	if !iptables.Exists("filter", "INPUT", rule...) {
		if _, err := iptables.Raw("-A", "INPUT", "-i", iface, "-j", "redwall-main"); err != nil {
			return err
		}
	}
	// create FORWARD chain jump rule if we should filter the docker network
	if filterDocker {
		rule := []string{
			"-i", iface,
			"-o", "docker0",
			"-j", "redwall-main"}
		if !iptables.Exists("filter", "FORWARD", rule...) {
			if _, err := iptables.Raw("-I", "FORWARD", "1", "-i", iface, "-o", "docker0", "-j", "redwall-main"); err != nil {
				return err
			}
		}
	}

	return nil
}

func applyWhitelistRules() error {
	var chain string = "redwall-whitelist"
	ips, err := getRedisSet("firewall:" + secGroup + ":whitelist")
	if err != nil {
		return err
	}

	// flush existing rules in the chain
	if _, err := iptables.Raw("-F", chain); err != nil {
		return fmt.Errorf("flushing iptables chain %q failed: %v", chain, err)
	}
	log.Debugf("flushed iptables chain %q", chain)

	for _, ip := range ips {
		testIP := net.ParseIP(ip)
		testCIDR, _, _ := net.ParseCIDR(ip)
		if testIP.To4() == nil && testCIDR.To4() == nil {
			log.Errorf("error adding whitelist rule: %v is not a valid IPv4 address or network", ip)
			continue
		}

		if _, err := iptables.Raw("-A", chain, "-s", ip, "-j", "ACCEPT"); err != nil {
			return err
		}
	}

	log.Infof("activated whitelist rules: %b IP entries", len(ips))

	return nil
}

func applyServicesRules() error {
	var chain string = "redwall-services"
	ports, err := getRedisSet("firewall:" + secGroup + ":services")
	if err != nil {
		return err
	}

	// flush the existing rules in the chain
	if _, err := iptables.Raw("-F", chain); err != nil {
		return fmt.Errorf("flushing iptables chain %q failed: %v", chain, err)
	}
	log.Debugf("flushed iptables chain %q", chain)

	for _, key := range ports {
		s := strings.Split(key, ":")
		if len(s) < 3 {
			log.Errorf("error adding port rule. invalid rule format: %s", key)
			continue
		}
		label, proto, port := s[0], s[1], s[2]
		if _, err := iptables.Raw("-A", chain, "-p", proto, "--dport", fmt.Sprint(port), "-j", "ACCEPT"); err != nil {
			return err
		}
		log.Infof("activated service -> name: %s protocol: %s port: %s", label, proto, port)
	}

	return nil
}

func flushChain(chain string) {
	if _, err := iptables.Raw("-F", chain); err != nil {
		log.Warningf("flushing iptables chain %q failed: %v", chain, err)
	}
	log.Debugf("flushed iptables chain %q", chain)
}

func deleteChain(chain string) {
	if _, err := iptables.Raw("-X", chain); err != nil {
		log.Warningf("deleting iptables chain %q failed: %v", chain, err)
	}
	log.Debugf("deleted iptables chain %q", chain)
}

func tearDownFirewall() error {
	log.Info("flushing iptables rules")
	//flushChain("INPUT")
	// delete jump rule from input
	rule := []string{
		"-i", iface,
		"-j", "redwall-main"}
	if iptables.Exists("filter", "INPUT", rule...) {
		if _, err := iptables.Raw("-D", "INPUT", "-i", iface, "-j", "redwall-main"); err != nil {
			log.Warningf("failed to remove input jump rule: %v", err)
		}
	}

	// delete jump rule from forward
	if filterDocker {
		rule := []string{
			"-i", iface,
			"-o", "docker0",
			"-j", "redwall-main"}
		if iptables.Exists("filter", "FORWARD", rule...) {
			if _, err := iptables.Raw("-D", "FORWARD", "-i", iface, "-o", "docker0", "-j", "redwall-main"); err != nil {
				log.Warningf("failed to remove docker jump rule: %v", err)
			}
		}

		log.Debugf("removed jump rule from FORWARD chain")
	}

	// flush user-defined chains
	flushChain("redwall-main")
	flushChain("redwall-services")
	flushChain("redwall-whitelist")
	flushChain("redwall-sshscan")
	// delete user-defined chains
	deleteChain("redwall-main")
	deleteChain("redwall-services")
	deleteChain("redwall-whitelist")
	deleteChain("redwall-sshscan")

	return nil
}
