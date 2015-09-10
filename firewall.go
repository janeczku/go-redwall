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

	// create INPUT chain jump rule
	if _, err = iptables.Raw("-A", "INPUT", "-i", iface, "-j", "redwall-main"); err != nil {
		return err
	}

	// create FORWARD chain jump rule if we shoud filter the docker network
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

	// allow SSH
	// iptables -A redwall-main -p tcp --dport 22 --ctstate NEW -j ACCEPT
	if allowSSH {
		if _, err := iptables.Raw("-A", chain, "-p", "tcp", "--dport", "22", "-m", "conntrack", "--ctstate", "NEW", "-j", "ACCEPT"); err != nil {
			return err
		}
	}

	// continue processing in redwall-whitelist
	if _, err := iptables.Raw("-A", chain, "-j", "redwall-whitelist"); err != nil {
		return err
	}

	// continue processing in redwall-services
	if _, err := iptables.Raw("-A", chain, "-j", "redwall-services"); err != nil {
		return err
	}

	// drop all other incoming packets on iface
	if _, err := iptables.Raw("-A", chain, "-j", "DROP"); err != nil {
		return err
	}

	log.Debugf("created boilerplate rules in redwall-main")
	return nil
}

// mitigate ssh bruteforce attacks
func initSSHRules() error {
	var chain string = "redwall-main"
	// iptables -I redwall-main 1 -p tcp --dport 22 -m state --state NEW -m recent --set --name SSH
	_, err := iptables.Raw("-I", chain, "2", "-p", "tcp", "--dport", "22", "-m", "state", "--state", "NEW",
		"-m", "recent", "--set", "--name", "SSH")
	if err != nil {
		return err
	}

	// iptables -I redwall-main 2 -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60
	// --hitcount 5 --name SSH --rttl -j REJECT --reject-with tcp-reset
	_, err = iptables.Raw("-I", chain, "3", "-p", "tcp", "--dport", "22", "-m", "state", "--state", "NEW",
		"-m", "recent", "--update", "--seconds", "60", "--hitcount", "5", "--name", "SSH", "-rttl", "-j", "REJECT",
		"--reject-with", "tcp-reset")
	if err != nil {
		return err
	}

	log.Debugf("created SSH attack mitigation rules in redwall-main")
	return nil
}

func applyWhitelistRules() error {
	var chain string = "redwall-whitelist"
	ips, err := getRedisSet("firewall:whitelist")
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

	log.Infof("activated whitelist rules: %v", ips)

	return nil
}

func applyServicesRules() error {
	var chain string = "redwall-services"
	ports, err := getRedisSet("firewall:services")
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
		if len(s) < 2 {
			log.Errorf("error adding port rule. invalid rule format: %s", key)
			continue
		}
		proto, port := s[0], s[1]
		if _, err := iptables.Raw("-A", chain, "-p", proto, "--dport", fmt.Sprint(port), "-j", "ACCEPT"); err != nil {
			return err
		}
	}

	log.Infof("activated services rules: %v", ports)

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

	// flush input chain

	flushChain("INPUT")

	// delete jump rule from forward

	if filterDocker {
		if _, err := iptables.Raw("-D", "FORWARD", "-i", iface, "-o", "docker0", "-j", "redwall-main"); err != nil {
			log.Warningf("failed to remove docker jump rule: %v", err)
		}
		log.Debugf("removed jump rule from FORWARD chain")
	}

	// flush user-defined chains

	flushChain("redwall-main")
	flushChain("redwall-services")
	flushChain("redwall-whitelist")

	// delete user-defined chains

	deleteChain("redwall-main")
	deleteChain("redwall-services")
	deleteChain("redwall-whitelist")

	return nil
}
