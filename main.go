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
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/garyburd/redigo/redis"
)

const (
	VERSION = "v0.2.0"
)

var (
	iface        string
	debug        bool
	version      bool
	redisHost    string
	redisPass    string
	filterDocker bool
	filterSSH    bool
	allowSSH     bool
)

func init() {
	// parse flags
	flag.BoolVar(&version, "version", false, "print version and exit")
	flag.BoolVar(&debug, "debug", false, "run in debug mode")
	flag.StringVar(&redisHost, "redis-host", "", "required: redis server address (host:port)")
	flag.StringVar(&redisPass, "redis-pass", "", "redis server password (leave empty to disable authentication)")
	flag.StringVar(&iface, "interface", "eth0", "name of public interface")
	flag.BoolVar(&filterDocker, "filter-docker", true, "filter docker container network (FORWARD chain)")
	flag.BoolVar(&filterSSH, "limit-ssh", false, "detect and limit SSH bruteforce attacks")
	flag.BoolVar(&allowSSH, "allow-ssh", true, "allow public access to SSH (port 22)")

	flag.Parse()

}

// cleaning up firewall rules on program exit
func shutdown() {
	log.Infof("terminating firedis daemon. resetting firewall rules.")
	tearDownFirewall()
}

func main() {

	// capture SIGINT / SIGTERM signals
	shutdownChan := make(chan os.Signal, 1)
	signal.Notify(shutdownChan, os.Interrupt)
	signal.Notify(shutdownChan, syscall.SIGTERM)
	go func() {
		<-shutdownChan
		shutdown()
		os.Exit(1)
	}()

	// set log level
	if debug || os.Getenv("FIREDIS_DEBUG") == "TRUE" {
		log.SetLevel(log.DebugLevel)
	}

	if version {
		fmt.Println(VERSION)
		return
	}

	if redisHost == "" {
		if os.Getenv("REDIS_HOST") != "" {
			redisHost = os.Getenv("REDIS_HOST")
		} else {
			fmt.Fprintf(os.Stderr, "Missing required argument: '-redis-host'\n")
			fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
			flag.PrintDefaults()
			return
		}
	}

	if redisPass == "" && os.Getenv("REDIS_PASS") != "" {
		redisPass = os.Getenv("REDIS_PASS")
	}

	if os.Getenv("ALLOW_SSH") == "FALSE" {
		allowSSH = false
	}

	// create Redis pool instance
	initConnPool(redisHost, redisPass)

	// wait until redis connection established
	for {
		conn := connPool.Get()
		_, err := conn.Do("ping")
		if err != nil {
			conn.Close()
			log.Warnf("connection to redis failed (reconnect in 5 secs): %v", err)
		} else {
			conn.Close()
			break
		}
		time.Sleep(5 * time.Second)
	}

	log.Infof("connected to redis at %s", redisHost)

	con := connPool.Get()
	resp, err := redis.String(con.Do("GET", "firewall:interface"))
	if err != nil && err != redis.ErrNil {
		log.Fatal(err)
	}

	if os.Getenv("PUBLIC_IFACE") != "" {
		iface = os.Getenv("PUBLIC_IFACE")
	} else if resp != "" {
		iface = resp
	}

	log.Infof("firewalling interface %q", iface)

	con.Close()

	log.Info("initializing the firewall...")

	// setup iptables chains
	if err := initChains(); err != nil {
		log.Fatal(err)
		return
	}

	// apply default rules
	if err := initDefaultRules(); err != nil {
		log.Fatal(err)
		return
	}

	// apply SSH attack mitigation rules
	if filterSSH || os.Getenv("LIMIT_SSH_ATTACKS") == "TRUE" {
		if err := initSSHRules(); err != nil {
			log.Fatal(err)
			return
		}
	}

	// apply services rules
	if err := applyServicesRules(); err != nil {
		log.Fatal(err)
		return
	}

	// apply ip whitelist rules
	if err := applyWhitelistRules(); err != nil {
		log.Fatal(err)
		return
	}

	// initialize PubSub client
	log.Debug("setting up pubsub client...")
	initPubSubClient(redisHost, redisPass)
	defer pubSubClient.TearDown()

	// monitor firewall rules keyspace
	log.Info("starting monitors...")
	go watchServices(pubSubClient)
	go watchWhitelist(pubSubClient)

	// run forever
	for {
		err := waitForDisconnect()
		log.Warnf("pubsub connection interrupted: %s", err)
		waitForReconnect()
		log.Info("pubsub connection re-established")
	}
}
