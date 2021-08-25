// Copyright 2021 Jeremy Rand.

// This file is part of safetlsa.
//
// safetlsa is free software: you can redistribute it and/or
// modify it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// safetlsa is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with safetlsa.  If not, see
// <https://www.gnu.org/licenses/>.

package safetlsa

import (
	"time"

	"gopkg.in/hlandau/easyconfig.v1/cflag"
)

var (
	flagGroup    = cflag.NewGroup(nil, "safetlsa")
	validityFlag = cflag.Int(flagGroup, "validity-short-term-seconds", 1*60*60,
		"Use the time of signing +/- this duration as the validity period "+
			"for short-term certificates.")
)

func ValidityShortTerm() time.Duration {
	return time.Duration(validityFlag.Value()) * time.Second
}
