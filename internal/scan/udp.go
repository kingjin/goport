package scan

// UDP probes. A UDP scan needs a request that a real service will answer:
// an empty datagram to 53, 123 or 161 is usually ignored, which would look the
// same as a filtered port. Well-formed probes make open ports answer, while
// closed ports still produce ICMP port-unreachable.
var (
	dnsProbe  = buildDNSQuery(0x1234, "www.example.com", 1)          // A record
	mdnsProbe = buildDNSQuery(0, "_services._dns-sd._udp.local", 12) // PTR
	ntpProbe  = buildNTPQuery()
	snmpProbe = buildSNMPGet()
	nbnsProbe = buildNBSTATQuery()
)

var (
	ssdpProbe = []byte("M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 1\r\n" +
		"ST: ssdp:all\r\n\r\n")
	sipProbe = []byte("OPTIONS sip:100@localhost SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-goport\r\n" +
		"Max-Forwards: 70\r\n" +
		"To: <sip:100@localhost>\r\n" +
		"From: <sip:goport@localhost>;tag=goport\r\n" +
		"Call-ID: goport@localhost\r\n" +
		"CSeq: 1 OPTIONS\r\n" +
		"Contact: <sip:goport@localhost:5060>\r\n" +
		"Content-Length: 0\r\n\r\n")
	ipmiProbe = []byte{0x06, 0x00, 0xff, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x20, 0x18, 0xc8, 0x81, 0x00, 0x38, 0x8e, 0x04, 0xb0}
)

// udpPayload returns the protocol-specific probe for a UDP port.
func udpPayload(port uint16) []byte {
	switch port {
	case 53:
		return dnsProbe
	case 123:
		return ntpProbe
	case 161, 162:
		return snmpProbe
	case 137:
		return nbnsProbe
	case 1900:
		return ssdpProbe
	case 5353:
		return mdnsProbe
	case 5060, 5061:
		return sipProbe
	case 623:
		return ipmiProbe
	}
	return nil
}

// buildDNSQuery assembles a DNS question with recursion desired.
func buildDNSQuery(id uint16, name string, qtype uint16) []byte {
	buf := make([]byte, 0, 12+len(name)+6)
	buf = append(buf, byte(id>>8), byte(id), 0x01, 0x00, // flags: RD
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	label := make([]byte, 0, 63)
	flush := func() {
		if len(label) == 0 {
			return
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
		label = label[:0]
	}
	for i := 0; i < len(name); i++ {
		if name[i] == '.' {
			flush()
			continue
		}
		label = append(label, name[i])
	}
	flush()
	buf = append(buf, 0x00)
	buf = append(buf, byte(qtype>>8), byte(qtype), 0x00, 0x01)
	return buf
}

// buildNTPQuery is a 48-byte NTPv3 client request.
func buildNTPQuery() []byte {
	b := make([]byte, 48)
	b[0] = 0x1b // LI 0, version 3, mode 3 (client)
	return b
}

// buildSNMPGet is a minimal SNMPv1 GetRequest for sysDescr.0 with community
// "public".
func buildSNMPGet() []byte {
	oid := []byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00}
	varbind := append([]byte{0x30, byte(2 + len(oid) + 2), 0x06, byte(len(oid))}, oid...)
	varbind = append(varbind, 0x05, 0x00)
	pduBody := []byte{0x02, 0x04, 0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00}
	pduBody = append(pduBody, 0x30, byte(len(varbind)))
	pduBody = append(pduBody, varbind...)
	pdu := append([]byte{0xa0, byte(len(pduBody))}, pduBody...)
	community := append([]byte{0x04, 0x06}, []byte("public")...)
	body := []byte{0x02, 0x01, 0x00}
	body = append(body, community...)
	body = append(body, pdu...)
	out := append([]byte{0x30, byte(len(body))}, body...)
	return out
}

// buildNBSTATQuery asks a NetBIOS name server for its node status ("*" query),
// which is what nbtscan uses to enumerate a Windows host.
func buildNBSTATQuery() []byte {
	b := []byte{0x82, 0x28, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	encoded := "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" // "*" in NetBIOS half-ASCII
	b = append(b, 0x20)
	b = append(b, []byte(encoded)...)
	b = append(b, 0x00, 0x00, 0x21, 0x00, 0x01)
	return b
}
