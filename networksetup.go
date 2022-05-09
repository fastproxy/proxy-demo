// inspire by https://github.com/fanpei91/sandwich-system-proxy/blob/master/sysproxy_darwin.go
package main

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

func setSystemProxy() (err error) {
	host := "127.0.0.1"
	port := "6789"
	networkservices := getNetworkInterfaces("default")

	for _, networkservice := range networkservices {
		cmd := exec.Command("sh", "-c", fmt.Sprintf("networksetup -setsecurewebproxy '%s' %s %s", networkservice, host, port))
		if out, err := cmd.CombinedOutput(); err != nil {
			return errors.New(string(out) + err.Error())
		}

		cmd = exec.Command("sh", "-c", fmt.Sprintf("networksetup -setwebproxy '%s' %s %s", networkservice, host, port))
		if out, err := cmd.CombinedOutput(); err != nil {
			return errors.New(string(out) + err.Error())
		}
	}

	return nil
}

func unsetSystemProxy() (err error) {
	networkservices := getNetworkInterfaces("default")
	for _, networkservice := range networkservices {
		cmd := exec.Command("sh", "-c", fmt.Sprintf("networksetup -setsecurewebproxystate '%s' %s", networkservice, "off"))
		if out, err := cmd.CombinedOutput(); err != nil {
			return errors.New(string(out) + err.Error())
		}

		cmd = exec.Command("sh", "-c", fmt.Sprintf("networksetup -setwebproxystate '%s' %s", networkservice, "off"))
		if out, err := cmd.CombinedOutput(); err != nil {
			return errors.New(string(out) + err.Error())
		}
	}

	return nil
}

func getNetworkInterfaces(mode string) []string {
	if mode == "default" {
		output := getDefaultNetworkInterface()
		return []string{output}
	}

	return getActivatedNetworkInterfaces()
}

func getDefaultNetworkInterface() string {
	c := exec.Command("sh", "-c", "networksetup -listnetworkserviceorder | grep -B 1 $(route -n get default | grep interface | awk '{print $2}') | head -n 1 | sed 's/.*) //'")
	out, err := c.CombinedOutput()
	if err != nil {
		return string(out)
	}
	output := strings.TrimSpace(string(out))
	if strings.Contains(output, "usage") {
		return "Wi-Fi"
	}
	return output
}

func getActivatedNetworkInterfaces() []string {
	c := exec.Command("sh", "-c", "networksetup -listnetworkserviceorder | grep 'Hardware Port'")
	out, err := c.CombinedOutput()
	if err != nil {
		return nil
	}

	interfacesMapping := map[string]string{}
	items := strings.Split(string(out), "\n")
	for _, line := range items {
		device, ns := parseDeviceAndInterface(line)
		if len(ns) > 0 {
			interfacesMapping[device] = ns
		}
	}

	c = exec.Command("sh", "-c", "ifconfig | pcregrep -M -o '^[^\t:]+(?=:([^\n]|\n\t)*status: active)'")
	out, err = c.CombinedOutput()
	if err != nil {
		return nil
	}

	var interfaces []string
	items = strings.Split(string(out), "\n")
	for _, device := range items {
		device = strings.TrimSpace(device)
		if len(device) > 0 {
			if ns, ok := interfacesMapping[device]; ok {
				interfaces = append(interfaces, ns)
			}
		}
	}

	return interfaces
}

func parseDeviceAndInterface(line string) (string, string) {
	if len(line) < 2 {
		return "", ""
	}

	if line[0] == '(' {
		line = line[1:]
	}

	if line[len(line)-1] == ')' {
		line = line[0 : len(line)-1]
	}

	items := strings.Split(line, ",")
	if len(items) < 2 {
		return "", ""
	}

	ns := strings.Split(items[0], ":")
	if len(ns) < 2 {
		return "", ""
	}
	device := strings.Split(items[1], ":")
	if len(device) < 2 {
		return "", ""
	}

	return strings.TrimSpace(device[1]), strings.TrimSpace(ns[1])
}
