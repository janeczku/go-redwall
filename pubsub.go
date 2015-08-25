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

	log "github.com/Sirupsen/logrus"
	"github.com/mcprohosting/redutil/pubsub"
)

var (
	// pubSubClient is a local redis PubSub instance
	pubSubClient *pubsub.Client
)

// Starts a new PubSub client instance
func initPubSubClient(server, password string) {
	pubSubClient = pubsub.New(server)
	go pubSubClient.Connect()
	pubSubClient.WaitFor(pubsub.ConnectedEvent)
}

// Listens for keyspace events for firewall:services
func watchServices(c *pubsub.Client) {
	listener := c.Listener(pubsub.Channel, "__keyspace@0__:firewall:services")
	//c.WaitFor(pubsub.SubscribeEvent)
	log.Info("monitoring firewall:services")
	defer listener.Unsubscribe()
	for range listener.Messages {
		log.Debug("processing service rules update")
		if err := applyServicesRules(); err != nil {
			log.Warnf("failed to process services rules update: %v", err)
		}
	}
}

// Listens for keyspace events for firewall:whitelist
func watchWhitelist(c *pubsub.Client) {
	listener := c.Listener(pubsub.Channel, "__keyspace@0__:firewall:whitelist")
	//c.WaitFor(pubsub.SubscribeEvent)
	log.Info("monitoring firewall:whitelist")
	defer listener.Unsubscribe()
	for range listener.Messages {
		log.Debug("processing whitelist rules update")
		if err := applyWhitelistRules(); err != nil {
			log.Warnf("failed to process whitelist rules update: %v", err)
		}
	}
}

// Blocks until Disconnected event occurs
func waitForDisconnect() error {
	ev := pubSubClient.WaitFor(pubsub.DisconnectedEvent)
	return fmt.Errorf("%v", ev.Packet)
}

// Blocks until Connected event occurs
func waitForReconnect() {
	pubSubClient.WaitFor(pubsub.ConnectedEvent)
}
