// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import "testing"

func TestRedactURLs(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{`no url here`, `no url here`},
		{`"https://mcp.example/sse"`, `"https://mcp.example/sse"`},
		{`"https://user:SECRETpass@mcp.example/?api_key=SECRET123"`, `"https://user:***@mcp.example/?api_key=***"`},
		{`http://u:SECRET@proxy.example/?k=SECRET`, `http://u:***@proxy.example/?k=***`},
		// A token written as the user name.
		{`https://ghp_SECRET@github.com/o/r.git`, `https://***@github.com/o/r.git`},
		// Placeholders name a variable and stay.
		{`https://${USER}:${PASS}@h/?key=${API_KEY}&t=$TOKEN`, `https://${USER}:${PASS}@h/?key=${API_KEY}&t=$TOKEN`},
		{`https://h/?a=1&&b=;c&d=`, `https://h/?a=***&&b=;***&d=`},
		{`https://h/p#access_token=SECRET&x=1`, `https://h/p#access_token=***&x=***`},
		{`https://h/p#section-2`, `https://h/p#section-2`},
		{`https://h/?q=SECRET#frag=SECRET`, `https://h/?q=***#frag=***`},
		// Inside a quoted permission entry or command.
		{`"Bash(curl https://h/?token=SECRET)"`, `"Bash(curl https://h/?token=***)"`},
		{`"Bash(curl https://h/?token=SECRET:*)"`, `"Bash(curl https://h/?token=***:*)"`},
		{"`curl -s wss://a:b@h:8443/x?y=z`", "`curl -s wss://a:***@h:8443/x?y=***`"},
		{`two: http://h/?a=SECRET and ftp://u:SECRET@h`, `two: http://h/?a=*** and ftp://u:***@h`},
	} {
		if got := RedactURLs(tc.in); got != tc.want {
			t.Errorf("RedactURLs(%q)\n got %q\nwant %q", tc.in, got, tc.want)
		}
	}
}
