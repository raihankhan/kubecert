package v1

import (
	"net"
	"net/url"
	"strings"
)

func (c *Certificate) GetSecretName() string {
	if c.Spec.SecretRef != nil {
		return c.Spec.SecretRef.Name
	}
	return strings.Join([]string{c.Name, "secret"}, "-")
}

func (c *Certificate) UpdateWithDefaultLabels(labels map[string]string) map[string]string {
	labels["app.kubernetes.io/instance"] = c.Name
	labels["app.kubernetes.io/component"] = "certificate"
	labels["app.kubernetes.io/managed-by"] = "kubecert"
	return labels
}

func (c *Certificate) UpdateWithDefaultSecretLabels(labels map[string]string) map[string]string {
	labels["app.kubernetes.io/issued-by"] = c.Name
	labels["app.kubernetes.io/component"] = "secret"
	labels["app.kubernetes.io/managed-by"] = "kubecert"
	return labels
}

func (c *Certificate) ConvertStringToIPAddresses() []net.IP {
	var ipList []net.IP
	for _, ip := range c.Spec.IPAddresses {
		parsedIP := net.ParseIP(ip)
		ipList = append(ipList, parsedIP)
	}
	return ipList
}

func (c *Certificate) ConvertStringToURLs() []*url.URL {
	var urlList []*url.URL
	for _, uri := range c.Spec.URIs {
		parsedURL, _ := url.Parse(uri)
		urlList = append(urlList, parsedURL)
	}
	return urlList
}
