package scanner

import (
    "fmt"
    "net"
    "sync"
    "time"
)

type ScanResult struct {
    Port    int
    State   string 
    Service string
}

// TCPConnectScan performs a TCP connect scan on the specified target and ports
// Returns a slice of ScanResult for open ports
func TCPConnectScan(target string, ports []int, timeout time.Duration) ([]ScanResult, error) {
    var results []ScanResult
    var mu sync.Mutex
    var wg sync.WaitGroup

    if target == "" {
        return nil, fmt.Errorf("target cannot be empty")
    }

    _, err := net.ResolveIPAddr("ip", target)
    if err != nil {
        return nil, fmt.Errorf("failed to resolve target: %v", err)
    }

    if timeout == 0 {
        timeout = 2 * time.Second
    }

    maxConcurrency := 100
    sem := make(chan struct{}, maxConcurrency)

    for _, port := range ports {
        wg.Add(1)
        sem <- struct{}{} 

        go func(port int) {
            defer wg.Done()
            defer func() { <-sem }() 

            address := net.JoinHostPort(target, fmt.Sprintf("%d", port))
            
            conn, err := net.DialTimeout("tcp", address, timeout)
            
            if err != nil {
                // Connection failed - port is likely closed or filtered
                // We can add more sophisticated error checking here
                return
            }
            
            
            conn.Close()
            
            mu.Lock()
            results = append(results, ScanResult{
                Port:    port,
                State:   "open",
                Service: GetServiceName(port), 
            })
            mu.Unlock()
        }(port)
    }

    wg.Wait()
    close(sem)

    return results, nil
}

// TCPConnectScanRange performs a TCP connect scan on a range of ports
// startPort and endPort are inclusive
func TCPConnectScanRange(target string, startPort, endPort int, timeout time.Duration) ([]ScanResult, error) {
    if startPort < 1 || endPort > 65535 || startPort > endPort {
        return nil, fmt.Errorf("invalid port range: must be between 1-65535 and start <= end")
    }

    ports := make([]int, 0, endPort-startPort+1)
    for port := startPort; port <= endPort; port++ {
        ports = append(ports, port)
    }

    return TCPConnectScan(target, ports, timeout)
}

// TCPConnectScanCommon scans the most common ports
func TCPConnectScanCommon(target string, timeout time.Duration) ([]ScanResult, error) {
    commonPorts := []int{
        21,    // FTP
        22,    // SSH
        23,    // Telnet
        25,    // SMTP
        53,    // DNS
        80,    // HTTP
        110,   // POP3
        111,   // RPC
        135,   // RPC
        139,   // NetBIOS
        143,   // IMAP
        443,   // HTTPS
        445,   // SMB
        993,   // IMAPS
        995,   // POP3S
        1723,  // PPTP
        3306,  // MySQL
        3389,  // RDP
        5432,  // PostgreSQL
        5900,  // VNC
        6379,  // Redis
        8080,  // HTTP-Alt
        8443,  // HTTPS-Alt
    }
    
    return TCPConnectScan(target, commonPorts, timeout)
}

// getServiceName returns the common service name for a port
func GetServiceName(port int) string {
    services := map[int]string{
        20:    "FTP-data",
        21:    "FTP",
        22:    "SSH",
        23:    "Telnet",
        25:    "SMTP",
        53:    "DNS",
        80:    "HTTP",
        110:   "POP3",
        111:   "RPCbind",
        119:   "NNTP",
        123:   "NTP",
        135:   "RPC",
        137:   "NetBIOS-ns",
        138:   "NetBIOS-dgm",
        139:   "NetBIOS-ssn",
        143:   "IMAP",
        161:   "SNMP",
        162:   "SNMP-trap",
        389:   "LDAP",
        443:   "HTTPS",
        445:   "SMB",
        465:   "SMTPS",
        514:   "Syslog",
        515:   "LPD",
        543:   "Kerberos",
        544:   "Kerberos",
        587:   "SMTP-submission",
        631:   "IPP",
        636:   "LDAPS",
        873:   "Rsync",
        990:   "FTPS",
        992:   "TelnetS",
        993:   "IMAPS",
        995:   "POP3S",
        1433:  "MSSQL",
        1521:  "Oracle",
        1723:  "PPTP",
        2049:  "NFS",
        2082:  "cPanel",
        2083:  "cPanelS",
        2086:  "WHM",
        2087:  "WHMS",
        2181:  "ZooKeeper",
        2375:  "Docker",
        2376:  "DockerS",
        3128:  "Squid",
        3306:  "MySQL",
        3389:  "RDP",
        3690:  "SVN",
        4333:  "MySQL-alt",
        4444:  "Metasploit",
        4500:  "IPsec",
        5000:  "UPnP",
        5432:  "PostgreSQL",
        5555:  "FreeSWITCH",
        5601:  "Kibana",
        5666:  "Nagios",
        5672:  "RabbitMQ",
        5800:  "VNC-http",
        5900:  "VNC",
        5984:  "CouchDB",
        6000:  "X11",
        6001:  "X11",
        6379:  "Redis",
        6660:  "IRC",
        6661:  "IRC",
        6662:  "IRC",
        6663:  "IRC",
        6664:  "IRC",
        6665:  "IRC",
        6666:  "IRC",
        6667:  "IRC",
        6668:  "IRC",
        6669:  "IRC",
        6679:  "IRC-SSL",
        6697:  "IRC-SSL",
        8000:  "HTTP-alt",
        8008:  "HTTP-alt",
        8009:  "AJP",
        8080:  "HTTP-proxy",
        8081:  "HTTP-alt",
        8086:  "InfluxDB",
        8087:  "HTTP-alt",
        8090:  "HTTP-alt",
        8118:  "Privoxy",
        8123:  "Polipo",
        8140:  "Puppet",
        8200:  "HTTP-alt",
        8222:  "HTTP-alt",
        8333:  "Bitcoin",
        8400:  "HTTP-alt",
        8443:  "HTTPS-alt",
        8500:  "HTTP-alt",
        8834:  "Nessus",
        8888:  "HTTP-alt",
        8983:  "Solr",
        9000:  "HTTP-alt",
        9042:  "Cassandra",
        9050:  "Tor",
        9090:  "HTTP-alt",
        9092:  "Kafka",
        9100:  "Jetdirect",
        9200:  "Elasticsearch",
        9300:  "Elasticsearch",
        9418:  "Git",
        9999:  "HTTP-alt",
        10000: "Webmin",
        11211: "Memcached",
        15672: "RabbitMQ",
        25565: "Minecraft",
        27017: "MongoDB",
        28017: "MongoDB-http",
        32400: "Plex",
        50000: "SAP",
        50030: "Hadoop",
        50060: "Hadoop",
        50070: "HDFS",
        50075: "HDFS",
        50090: "HDFS",
        60000: "HTTP-alt",
    }
    
    if name, exists := services[port]; exists {
        return name
    }
    return "unknown"
}
