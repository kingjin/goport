package scan

import "fmt"

// serviceNames maps well-known port numbers to service names, mirroring what
// Goby shows in its scan results. The table is deliberately conservative:
// unknown ports render as an empty string, and banner/version detection can
// still override the guess.
var serviceNames = map[uint16]string{
	20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain",
	67: "dhcp", 68: "dhcp", 69: "tftp", 79: "finger", 80: "http", 81: "http",
	88: "kerberos", 102: "s7comm", 110: "pop3", 111: "rpcbind", 113: "ident",
	119: "nntp", 123: "ntp", 135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm",
	139: "netbios-ssn", 143: "imap", 161: "snmp", 162: "snmptrap", 179: "bgp",
	199: "smux", 389: "ldap", 427: "svrloc", 443: "https", 444: "snpp",
	445: "microsoft-ds", 464: "kpasswd", 465: "smtps", 500: "isakmp", 502: "modbus",
	512: "exec", 513: "login", 514: "shell", 515: "printer", 520: "router",
	548: "afp", 554: "rtsp", 587: "submission", 623: "asf-rmcp", 631: "ipp",
	636: "ldaps", 646: "ldp", 873: "rsync", 888: "accessbuilder", 902: "vmware-auth",
	989: "ftps-data", 990: "ftps", 993: "imaps", 995: "pop3s", 1025: "nfs-or-iis",
	1080: "socks", 1099: "rmiregistry", 1112: "icp", 1194: "openvpn", 1241: "nessus",
	1311: "dell-openmanage", 1337: "waste", 1433: "ms-sql-s", 1434: "ms-sql-m",
	1521: "oracle", 1533: "sapr3", 1583: "pyrscope", 1701: "l2tp", 1720: "h323q931",
	1723: "pptp", 1755: "msmq", 1812: "radius", 1813: "radius-acct", 1883: "mqtt",
	1900: "upnp", 2000: "cisco-sccp", 2049: "nfs", 2082: "cpanel", 2083: "cpanel-ssl",
	2100: "amx-axbnet", 2181: "zookeeper", 2222: "ethernet-ip", 2323: "telnet",
	2375: "docker", 2376: "docker-ssl", 2379: "etcd", 2425: "flir", 2638: "sybase",
	3000: "ppp", 3050: "firebird", 3128: "squid", 3200: "tick-port", 3260: "iscsi",
	3268: "msft-gc", 3269: "msft-gc-ssl", 3306: "mysql", 3389: "ms-wbt-server",
	3478: "stun", 3493: "nut", 3535: "ms-la", 3690: "svn", 4000: "icccad",
	4045: "lockd", 4369: "erlang-epmd", 4444: "krb524", 4505: "salt", 4506: "salt-master",
	4567: "tram", 4730: "gearman", 4840: "opcua", 4848: "glassfish", 5000: "upnp",
	5001: "commplex-link", 5009: "airport-admin", 5060: "sip", 5061: "sips",
	5222: "xmpp-client", 5269: "xmpp-server", 5353: "mdns", 5355: "llmnr",
	5432: "postgresql", 5433: "postgresql", 5555: "freeciv", 5601: "kibana",
	5632: "pcanywhere", 5666: "nrpe", 5672: "amqp", 5683: "coap", 5800: "vnc-http",
	5900: "vnc", 5901: "vnc-1", 5938: "teamviewer", 5984: "couchdb", 5985: "wsman",
	5986: "wsmans", 6000: "x11", 6001: "x11-1", 6080: "novnc", 61616: "activemq",
	6379: "redis", 6443: "kubernetes", 6667: "irc", 7001: "weblogic", 7002: "weblogic-ssl",
	7077: "spark", 7199: "cassandra-jmx", 7474: "neo4j", 7547: "cwmp", 8000: "http-alt",
	8008: "http", 8009: "ajp13", 8010: "xmpp", 8020: "sap", 8023: "art", 8032: "pro-ed",
	8042: "motorola", 8069: "odoo", 8080: "http-proxy", 8081: "http-alt", 8082: "http-alt",
	8086: "influxdb", 8088: "http-alt", 8090: "http-alt", 8098: "http-alt",
	8161: "activemq", 8180: "http-alt", 8200: "trivy", 8300: "tmi", 8333: "bitcoin",
	8443: "https-alt", 8484: "http-alt", 8500: "consul", 8530: "http-alt", 8545: "ethereum",
	8686: "sun-as-jmxrmi", 8834: "nessus", 8880: "http-alt", 8888: "sun-answerbook",
	8899: "ospf-lite", 8983: "solr", 9000: "cslistener", 9001: "tor-orport",
	9042: "cassandra", 9060: "websphere", 9080: "glrpc", 9090: "zeus-admin",
	9092: "kafka", 9100: "jetdirect", 9160: "cassandra-thrift", 9200: "elasticsearch",
	9300: "elasticsearch-cluster", 9418: "git", 9443: "https-alt", 9600: "omron-fins",
	9999: "abyss", 10000: "webmin", 10050: "zabbix-agent", 10051: "zabbix-trapper",
	10250: "kubelet", 10255: "kubelet-readonly", 11211: "memcached", 11333: "http-alt",
	12345: "netbus", 15672: "rabbitmq-mgmt", 16379: "redis-alt", 18080: "http-alt",
	20000: "dnp3", 25565: "minecraft", 27017: "mongodb", 27018: "mongodb",
	28017: "mongodb-http", 30000: "ndmps", 32764: "router-sys", 37777: "dahua-dvr",
	44818: "ethernet-ip", 47808: "bacnet", 49152: "upnp", 50000: "sap", 50013: "http-alt",
	50050: "cobalt-strike", 50070: "hdfs-namenode", 55000: "bacnet",
	62078: "iphone-sync", 65535: "unknown",
}

// ServiceName returns the well-known service for a port, or "" when unknown.
func ServiceName(port uint16) string { return serviceNames[port] }

// ServiceSummary describes a port for humans, e.g. "http (80/tcp)".
func ServiceSummary(port uint16, proto string) string {
	if name := ServiceName(port); name != "" {
		return fmt.Sprintf("%s (%d/%s)", name, port, proto)
	}
	return fmt.Sprintf("%d/%s", port, proto)
}
