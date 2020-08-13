/*
 * Copyright (c) Sematext Group, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 */

package remove

import (
	"github.com/Ben-L-E/oxdpus/pkg/blacklist"
	"github.com/Ben-L-E/oxdpus/pkg/iprange"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"net"
	"strings"
)

func NewCommand(logger *logrus.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Removes an IP address from the blacklist",
		Run: func(cmd *cobra.Command, args []string) {
			mapnum, _ := cmd.Flags().GetString("map")
			if len(mapnum) > 0 {
    			blacklist.BlacklistMap = "blacklist" + mapnum
			}
			ip, _ := cmd.Flags().GetString("ip")
			m, err := blacklist.NewMap()
			if err != nil {
				logger.Fatal(err)
			}
			// IP range is specified in CIDR notation
			if strings.Contains(ip, "/") {
				addrs, err := iprange.FromCIDR(ip)
				if err != nil {
					logger.Fatal(err)
				}
				for _, addr := range addrs {
					if m.Remove(net.ParseIP(addr)); err != nil {
						logger.Warnf("fail to remove %s IP address from the blacklist", addr)
						continue
					}
				}
				logger.Infof("%d addresses removed from the blacklist", len(addrs))
				return
			}
			if m.Remove(net.ParseIP(ip)); err != nil {
				logger.Error(err)
				return
			}
			logger.Infof("%s address removed from the blacklist", ip)
		},
	}
	return cmd
}
