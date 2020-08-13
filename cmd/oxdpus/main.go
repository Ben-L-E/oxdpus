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

package main

import (
	"github.com/Ben-L-E/oxdpus/cmd/oxdpus/root"
)

func main() {
	if err := root.Get().Execute(); err != nil {
		panic(err)
	}
}
