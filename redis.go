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
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/garyburd/redigo/redis"
)

var (
	// connPool is a local redis connection pool instance
	connPool *redis.Pool
)

func initConnPool(server, password string) {
	connPool = &redis.Pool{
		MaxIdle:     3,
		IdleTimeout: 240 * time.Second,
		Dial: func() (redis.Conn, error) {
			if conn, err := redis.Dial("tcp", server); err != nil {
				return nil, err
			} else {
				if password != "" {
					if _, err := conn.Do("AUTH", password); err != nil {
						conn.Close()
						return nil, err
					}
				}
				return conn, nil
			}
		},
		TestOnBorrow: pingRedis,
	}
}

func pingRedis(c redis.Conn, t time.Time) error {
	_, err := c.Do("ping")
	if err != nil {
		log.Warnf("redis ping failed: %v", err)
	}
	return err
}

// Gets all members of set 'key' and returns them as []string
func getRedisSet(key string) ([]string, error) {
	conn := connPool.Get()
	defer conn.Close()
	members, err := redis.Strings(conn.Do("SMEMBERS", key))
	if err != nil {
		return nil, err
	}
	return members, nil
}
