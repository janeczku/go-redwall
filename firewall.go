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
	"github.com/janeczku/firedis/iptables"
)

// create user chains and jump rules in INPUT and FORWARD chain
func initChains() error {

	// create user chains
	if _, err := iptables.Raw("-N", "firedis-main"); err != nil {
		return err
	}

	if _, err := iptables.Raw("-N", "firedis-whitelist"); err != nil {
		return err
	}

	if _, err := iptables.Raw("-N", "firedis-services"); err != nil {
		return err
	}

	// set default policy to ACCEPT
	if _, err := iptables.Raw("-P", "INPUT", "ACCEPT"); err != nil {
		return err
	}

	if _, err := iptables.Raw("-P", "FORWARD", "ACCEPT"); err != nil {
		return err
	}

	// flush INPUT chain
	if _, err := iptables.Raw("-F", "INPUT"); err != nil {
		return err
	}

	// create INPUT chain jump rule
	if _, err := iptables.Raw("-A", "INPUT", "-i", iface, "-j", "firedis-main"); err != nil {
		return err
	}

	// create FORWARD chain jump rule if we shoud filter the docker network
	if filterDocker {
		rule := []string{
			"-i", iface,
			"-o", "docker0",
			"-j", "firedis-main"}
		if !iptables.Exists("filter", "FORWARD", rule...) {
			if _, err := iptables.Raw("-I", "FORWARD", "1", "-i", iface, "-o", "docker0", "-j", "firedis-main"); err != nil {
				return err
			}
		}
	}

	log.Debugf("created firedis user chains")
	return nil
}

// Create the boilerplate rules in firedis-main
func initDefaultRules() error {
	var chain string = "firedis-main"

	// allow established/related conns
	// iptables -A firedis-main -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
	if _, err := iptables.Raw("-A", chain, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"); err != nil {
		return err
	}

	// block null packets
	// iptables -A firedis-main -p tcp --tcp-flags ALL NONE -j DROP
	if _, err := iptables.Raw("-A", chain, "-p", "tcp", "--tcp-flags", "ALL", "NONE", "-j", "DROP"); err != nil {
		return err
	}

	// block XMAS packets
	// iptables -A firedis-main -p tcp --tcp-flags ALL ALL -j DROP
	if _, err := iptables.Raw("-A", chain, "-p", "tcp", "--tcp-flags", "ALL", "ALL", "-j", "DROP"); err != nil {
		return err
	}

	// block invalid packets
	// iptables -A firedis-main -m conntrack --ctstate INVALID -j DROP
	if _, err := iptables.Raw("-A", chain, "-m", "conntrack", "--ctstate", "INVALID", "-j", "DROP"); err != nil {
		return err
	}

	// block remote packets claiming to be from a loopback address.
	// iptables -A firedis-main -s 127.0.0.0/8 -j DROP
	if _, err := iptables.Raw("-A", chain, "-s", "127.0.0.0/8", "-j", "DROP"); err != nil {
		return err
	}

	// allow ICMP ping
	// iptables -A firedis-main -p icmp --icmp-type 8 -m conntrack --ctstate NEW -j ACCEPT
	if _, err := iptables.Raw("-A", chain, "-p", "icmp", "--icmp-type", "8", "-m", "conntrack", "--ctstate", "NEW", "-j", "ACCEPT"); err != nil {
		return err
	}

	// allow SSH
	// iptables -A firedis-main -p tcp --dport 22 --ctstate NEW -j ACCEPT
	if _, err := iptables.Raw("-A", chain, "-p", "tcp", "--dport", "22", "-m", "conntrack", "--ctstate", "NEW", "-j", "ACCEPT"); err != nil {
		return err
	}

	// continue processing in firedis-whitelist
	if _, err := iptables.Raw("-A", chain, "-j", "firedis-whitelist"); err != nil {
		return err
	}

	// continue processing in firedis-services
	if _, err := iptables.Raw("-A", chain, "-j", "firedis-services"); err != nil {
		return err
	}

	// drop all other incoming packets on iface
	if _, err := iptables.Raw("-A", chain, "-j", "DROP"); err != nil {
		return err
	}

	log.Debugf("created boilerplate rules in firedis-main")
	return nil
}

// mitigate ssh bruteforce attacks
func initSSHRules() error {
	var chain string = "firedis-main"
	// iptables -I firedis-main 1 -p tcp --dport 22 -m state --state NEW -m recent --set --name SSH
	_, err := iptables.Raw("-I", chain, "2", "-p", "tcp", "--dport", "22", "-m", "state", "--state", "NEW",
		"-m", "recent", "--set", "--name", "SSH")
	if err != nil {
		return err
	}

	// iptables -I firedis-main 2 -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60
	// --hitcount 5 --name SSH --rttl -j REJECT --reject-with tcp-reset
	_, err = iptables.Raw("-I", chain, "3", "-p", "tcp", "--dport", "22", "-m", "state", "--state", "NEW",
		"-m", "recent", "--update", "--seconds", "60", "--hitcount", "5", "--name", "SSH", "-rttl", "-j", "REJECT",
		"--reject-with", "tcp-reset")
	if err != nil {
		return err
	}

	log.Debugf("created SSH attack mitigation rules in firedis-main")
	return nil
}

func applyWhitelistRules() error {
	var chain string = "firedis-whitelist"
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
	var chain string = "firedis-services"
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
		if _, err := iptables.Raw("-D", "FORWARD", "-i", iface, "-o", "docker0", "-j", "firedis-main"); err != nil {
			log.Warningf("failed to remove docker jump rule: %v", err)
		}
		log.Debugf("removed jump rule from FORWARD chain")
	}

	// flush user-defined chains

	flushChain("firedis-main")
	flushChain("firedis-services")
	flushChain("firedis-whitelist")

	// delete user-defined chains

	deleteChain("firedis-main")
	deleteChain("firedis-services")
	deleteChain("firedis-whitelist")

	return nil
}
