/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * Well-known port-to-service mappings for TCP service identification.
 */
export const PORT_SERVICE_MAP = new Map<number, string>([
	[21, 'ftp'],
	[22, 'ssh'],
	[23, 'telnet'],
	[25, 'smtp'],
	[53, 'dns'],
	[69, 'tftp'],
	[80, 'http'],
	[88, 'kerberos'],
	[110, 'pop3'],
	[111, 'rpcbind'],
	[119, 'nntp'],
	[123, 'ntp'],
	[135, 'msrpc'],
	[137, 'netbios-ns'],
	[138, 'netbios-dgm'],
	[139, 'netbios-ssn'],
	[143, 'imap'],
	[161, 'snmp'],
	[162, 'snmptrap'],
	[179, 'bgp'],
	[389, 'ldap'],
	[443, 'https'],
	[445, 'microsoft-ds'],
	[464, 'kpasswd'],
	[465, 'smtps'],
	[500, 'isakmp'],
	[512, 'exec'],
	[513, 'login'],
	[514, 'shell'],
	[515, 'printer'],
	[520, 'rip'],
	[523, 'ibm-db2'],
	[524, 'ncp'],
	[548, 'afp'],
	[554, 'rtsp'],
	[587, 'submission'],
	[593, 'http-rpc-epmap'],
	[623, 'ipmi'],
	[631, 'ipp'],
	[636, 'ldaps'],
	[873, 'rsync'],
	[902, 'vmware-auth'],
	[993, 'imaps'],
	[995, 'pop3s'],
	[1025, 'nfs-or-iis'],
	[1080, 'socks'],
	[1099, 'java-rmi'],
	[1194, 'openvpn'],
	[1433, 'mssql'],
	[1434, 'mssql-m'],
	[1521, 'oracle'],
	[1723, 'pptp'],
	[1883, 'mqtt'],
	[2049, 'nfs'],
	[2082, 'cpanel'],
	[2083, 'cpanel-ssl'],
	[2100, 'ftp-proxy'],
	[2121, 'ftp-alt'],
	[2181, 'zookeeper'],
	[2222, 'ssh-alt'],
	[2375, 'docker'],
	[2376, 'docker-ssl'],
	[2483, 'oracle-tns'],
	[2484, 'oracle-tns-ssl'],
	[3000, 'grafana'],
	[3268, 'globalcatalog'],
	[3269, 'globalcatalog-ssl'],
	[3306, 'mysql'],
	[3389, 'rdp'],
	[3690, 'svn'],
	[4443, 'https-alt'],
	[4505, 'saltstack'],
	[4506, 'saltstack'],
	[4848, 'glassfish'],
	[5000, 'upnp'],
	[5001, 'synology'],
	[5432, 'postgresql'],
	[5555, 'adb'],
	[5601, 'kibana'],
	[5672, 'amqp'],
	[5900, 'vnc'],
	[5984, 'couchdb'],
	[5985, 'winrm'],
	[5986, 'winrm-ssl'],
	[6379, 'redis'],
	[6443, 'kubernetes-api'],
	[6667, 'irc'],
	[7001, 'weblogic'],
	[7002, 'weblogic-ssl'],
	[7070, 'realserver'],
	[7443, 'oracleAS'],
	[8000, 'http-alt'],
	[8008, 'http-alt'],
	[8009, 'ajp13'],
	[8042, 'hadoop'],
	[8080, 'http-proxy'],
	[8081, 'http-alt'],
	[8082, 'http-alt'],
	[8083, 'http-alt'],
	[8084, 'http-alt'],
	[8085, 'http-alt'],
	[8086, 'influxdb'],
	[8088, 'http-alt'],
	[8089, 'splunkd'],
	[8090, 'http-alt'],
	[8161, 'activemq'],
	[8200, 'vault'],
	[8291, 'mikrotik'],
	[8333, 'bitcoin'],
	[8443, 'https-alt'],
	[8500, 'consul'],
	[8834, 'nessus'],
	[8888, 'http-alt'],
	[9000, 'sonarqube'],
	[9001, 'tor'],
	[9042, 'cassandra'],
	[9090, 'prometheus'],
	[9091, 'transmission'],
	[9100, 'jetdirect'],
	[9200, 'elasticsearch'],
	[9300, 'elasticsearch'],
	[9418, 'git'],
	[9443, 'https-alt'],
	[9999, 'abyss'],
	[10000, 'webmin'],
	[10250, 'kubelet'],
	[10443, 'https-alt'],
	[11211, 'memcached'],
	[11443, 'https-alt'],
	[15672, 'rabbitmq-mgmt'],
	[16080, 'http-alt'],
	[17000, 'vault-agent'],
	[27017, 'mongodb'],
	[27018, 'mongodb'],
	[28017, 'mongodb-web'],
	[44818, 'ethernetip'],
	[47001, 'winrm'],
	[49152, 'msrpc'],
	[50000, 'sap'],
	[50070, 'hadoop-namenode'],
	[61616, 'activemq'],
]);

/**
 * Top 100 most scanned TCP ports.
 */
export const TOP_100_PORTS: number[] = [
	7, 20, 21, 22, 23, 25, 53, 69, 80, 88, 110, 111, 119, 123,
	135, 137, 139, 143, 161, 179, 389, 443, 445, 464, 465, 500,
	514, 515, 548, 554, 587, 631, 636, 873, 993, 995, 1025, 1080,
	1099, 1194, 1433, 1521, 1723, 1883, 2049, 2082, 2121, 2181,
	2222, 2375, 3000, 3268, 3306, 3389, 3690, 4443, 4848, 5000,
	5432, 5555, 5601, 5672, 5900, 5984, 5985, 6379, 6443, 6667,
	7001, 7443, 8000, 8008, 8009, 8042, 8080, 8081, 8086, 8088,
	8089, 8161, 8200, 8443, 8500, 8834, 8888, 9000, 9042, 9090,
	9100, 9200, 9418, 10000, 10250, 11211, 15672, 27017, 44818,
	50000, 50070, 61616
];

/**
 * Top 1000 most scanned TCP ports (nmap default).
 */
export const TOP_1000_PORTS: number[] = (() => {
	const ports = new Set<number>(TOP_100_PORTS);
	// Add common ranges
	for (let p = 1; p <= 1024; p++) { ports.add(p); }
	// Common high ports
	const highPorts = [
		1025, 1026, 1027, 1028, 1029, 1030, 1080, 1099, 1194,
		1214, 1241, 1311, 1337, 1433, 1434, 1500, 1521, 1588,
		1720, 1723, 1755, 1883, 1900, 1935, 2000, 2001, 2049,
		2082, 2083, 2100, 2121, 2181, 2222, 2375, 2376, 2483,
		2484, 3000, 3001, 3128, 3268, 3269, 3306, 3389, 3478,
		3690, 4000, 4200, 4443, 4444, 4505, 4506, 4567, 4848,
		5000, 5001, 5050, 5060, 5222, 5269, 5357, 5432, 5555,
		5601, 5631, 5632, 5672, 5800, 5900, 5901, 5984, 5985,
		5986, 6000, 6001, 6379, 6443, 6588, 6666, 6667, 6668,
		6697, 7000, 7001, 7002, 7070, 7443, 7777, 7778, 8000,
		8001, 8008, 8009, 8010, 8042, 8080, 8081, 8082, 8083,
		8084, 8085, 8086, 8087, 8088, 8089, 8090, 8091, 8161,
		8200, 8291, 8333, 8443, 8444, 8500, 8765, 8834, 8880,
		8888, 8889, 9000, 9001, 9002, 9042, 9080, 9090, 9091,
		9100, 9200, 9300, 9418, 9443, 9999, 10000, 10250, 10443,
		11211, 11443, 12345, 13337, 15672, 16080, 17000, 20000,
		25565, 27017, 27018, 28017, 30000, 31337, 32768, 33060,
		44818, 47001, 49152, 49153, 49154, 49155, 50000, 50070,
		54321, 55555, 61616, 65535,
	];
	for (const p of highPorts) { ports.add(p); }
	return Array.from(ports).sort((a, b) => a - b);
})();

export function lookupService(port: number): string {
	return PORT_SERVICE_MAP.get(port) ?? 'unknown';
}

export function parsePorts(spec: string): number[] {
	const trimmed = spec.trim().toLowerCase();
	if (trimmed === 'top100') { return [...TOP_100_PORTS]; }
	if (trimmed === 'top1000') { return [...TOP_1000_PORTS]; }
	if (trimmed === 'all') {
		const ports: number[] = [];
		for (let p = 1; p <= 65535; p++) { ports.push(p); }
		return ports;
	}

	const result = new Set<number>();
	const segments = trimmed.split(',');
	for (const segment of segments) {
		const rangeMatch = segment.trim().match(/^(\d+)\s*-\s*(\d+)$/);
		if (rangeMatch) {
			const start = parseInt(rangeMatch[1], 10);
			const end = parseInt(rangeMatch[2], 10);
			if (start >= 1 && end <= 65535 && start <= end) {
				for (let p = start; p <= end; p++) { result.add(p); }
			}
		} else {
			const port = parseInt(segment.trim(), 10);
			if (port >= 1 && port <= 65535) { result.add(port); }
		}
	}
	return Array.from(result).sort((a, b) => a - b);
}
