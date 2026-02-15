import pyshark
import asyncio

# ================= FIX ASYNCIO FOR FLASK THREADS =================
def fix_asyncio():
    try:
        asyncio.get_event_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())

# ================= MAIN SCAN FUNCTION =================
def scan_pcap(filepath):
    fix_asyncio()   # REQUIRED FOR FLASK THREADS
    
    # Optional: Set tshark path if needed (Windows)
    TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"
    
    # Lists and dictionaries to store findings
    insecureProtocols = []      # Stores detected insecure protocols 
    portMismatches = []         # Stores detected port/protocol mismatches 
    vulnTlsVersions = []        # Stores detected vulnerable TLS versions 
    unencryptedCreds = []       # Stores detected plain text cred protocols 
    
    # Counters
    protocolCounter = {}        # Tracks number of packets seen per protocol
    totalPackets = 0            # Tracks total number of packets scanned
    tcp_packets = 0             # Tracks TCP packets
    udp_packets = 0             # Tracks UDP packets
    unique_ips = set()          # Tracks unique IP addresses
    packets = []                # Stores packet details for dashboard table
    
    # Scan for any known insecure protocols
    def scanInsecureProtocols(packet):
        # List of insecure protocols to check for
        protocolsToCheck = ['ftp', 'telnet', 'ssl', 'http']
        
        for proto in protocolsToCheck:
            # Checks for protocol layer
            if hasattr(packet, proto):
                protoUpper = proto.upper()
    
                # Track each protocol only once in the results list
                if protoUpper not in insecureProtocols:
                    insecureProtocols.append(protoUpper)
                # Count number of packets that use this protocol
                protocolCounter[protoUpper] = protocolCounter.get(protoUpper, 0) + 1
    
    
    # Check if common ports are used by correct protocols
    def checkPortProtocolMismatch(packet):
     
        # Highest-level protocol identified by Pyshark
        protocol = packet.highest_layer
        
        # Get port numbers if TCP or UDP layer exists
        srcPort = None
        dstPort = None
        transport = None
        
        # Determine whether the packet uses TCP or UDP
        if hasattr(packet, 'tcp'):
            srcPort = int(packet.tcp.srcport)
            dstPort = int(packet.tcp.dstport)
            transport = 'TCP'
        elif hasattr(packet, 'udp'):
            srcPort = int(packet.udp.srcport)
            dstPort = int(packet.udp.dstport)
            transport = 'UDP'
        
        # If there are no ports, nothing to check
        if srcPort is None:
            return
        
        # Check port 22 (should be SSH)
        if 22 in [srcPort, dstPort]:
            if protocol != 'SSH':
                hasSSH = hasattr(packet, 'ssh')
                if not hasSSH:
                    mismatch = f"Port 22 used by {protocol} (expected SSH)"
                    if mismatch not in portMismatches:
                        portMismatches.append(mismatch)
        
        # Check port 80 (should be HTTP)
        if 80 in [srcPort, dstPort]:
            if protocol != 'HTTP':
                hasHTTP = hasattr(packet, 'http')
                if not hasHTTP and transport == 'TCP':
                    mismatch = f"Port 80 used by {protocol} (expected HTTP)"
                    if mismatch not in portMismatches:
                        portMismatches.append(mismatch)
        
        # Check port 53 (should be DNS on UDP, not TCP)
        if 53 in [srcPort, dstPort]:
            if transport == 'TCP':
                mismatch = f"Port 53 using TCP (expected UDP for DNS)"
                if mismatch not in portMismatches:
                    portMismatches.append(mismatch)
    
    
    # Task 3: Check for vulnerable TLS versions (1.0 and 1.1)
    def checkVulnTls(packet):
    
        if hasattr(packet, 'tls'):
            try:
                # TLS version is found in the handshake
                if hasattr(packet.tls, 'handshake_version'):
                    versionHex = packet.tls.handshake_version
                    
                    # Check for TLS 1.0
                    if versionHex == '0x0301':
                        if 'TLS 1.0' not in vulnTlsVersions:
                            vulnTlsVersions.append('TLS 1.0')
                    
                    # Check for TLS 1.1
                    elif versionHex == '0x0302':
                        if 'TLS 1.1' not in vulnTlsVersions:
                            vulnTlsVersions.append('TLS 1.1')
                    
            except AttributeError:
                pass
    
    
    # Scanning for any unencrypted credentials
    def checkUnencryptedCreds(packet):
    
        protocol = packet.highest_layer
        
        # Check FTP for USER/PASS commands
        if hasattr(packet, 'ftp'):
            try:
                if hasattr(packet.ftp, 'request_command'):
                    command = packet.ftp.request_command
                    if command in ['USER', 'PASS']:
                        credential = f'FTP {command} command in cleartext'
                        if credential not in unencryptedCreds:
                            unencryptedCreds.append(credential)
            except AttributeError:
                pass
        
        # Telnet authentication is always plaintext
        if protocol == 'TELNET':
            credential = 'Telnet authentication (all plaintext)'
            if credential not in unencryptedCreds:
                unencryptedCreds.append(credential)
        
        # HTTP Basic Authentication uses Base64, which is not encryption
        if hasattr(packet, 'http'):
            try:
                if hasattr(packet.http, 'authorization'):
                    auth = packet.http.authorization
                    if 'Basic' in auth:
                        credential = 'HTTP Basic Auth (Base64 encoded only)'
                        if credential not in unencryptedCreds:
                            unencryptedCreds.append(credential)
            except AttributeError:
                pass
        
        # SMTP AUTH indicates email credentials sent without encryption
        if hasattr(packet, 'smtp'):
            try:
                if hasattr(packet.smtp, 'req_command'):
                    command = packet.smtp.req_command
                    if command == 'AUTH':
                        credential = 'SMTP AUTH command (plaintext email authentication)'
                        if credential not in unencryptedCreds:
                            unencryptedCreds.append(credential)
            except AttributeError:
                pass
    
        # POP3 uses USER and PASS commands similar to FTP 
        if hasattr(packet, 'pop'):
            try:
                # POP3 uses USER and PASS commands like FTP
                if hasattr(packet.pop, 'request_command'):
                    command = packet.pop.request_command
                    if command in ['USER', 'PASS']:
                        credential = f'POP3 {command} (cleartext email credentials)'
                        if credential not in unencryptedCreds:
                            unencryptedCreds.append(credential)
            except AttributeError:
                pass
        
        # IMAP authentication commonly uses LOGIN commands
        if hasattr(packet, 'imap'):
            try:
                # IMAP authentication can be detected by LOGIN command
                if hasattr(packet.imap, 'request'):
                    request = str(packet.imap.request)
                    if 'LOGIN' in request.upper():
                        credential = 'IMAP LOGIN (cleartext email credentials)'
                        if credential not in unencryptedCreds:
                            unencryptedCreds.append(credential)
            except AttributeError:
                pass
    
    # ================= OPEN CAPTURE FILE =================
    try:
        # Try with tshark path first (Windows), fall back to default
        try:
            capture = pyshark.FileCapture(
                filepath,
                tshark_path=TSHARK_PATH,
                keep_packets=False
            )
        except:
            # Fallback for Linux/Mac or if tshark path is wrong
            capture = pyshark.FileCapture(
                filepath,
                keep_packets=False
            )
        
        # ================= PACKET LOOP =================
        for packet in capture:
            totalPackets += 1
            
            try:
                # Get protocol information
                protocol = packet.highest_layer
                
                # Track IP addresses
                if hasattr(packet, 'ip'):
                    src = packet.ip.src
                    dst = packet.ip.dst
                    unique_ips.add(src)
                    unique_ips.add(dst)
                else:
                    src = "N/A"
                    dst = "N/A"
                
                # Count TCP and UDP packets
                if hasattr(packet, 'tcp'):
                    tcp_packets += 1
                if hasattr(packet, 'udp'):
                    udp_packets += 1
                
                # Save packet details for dashboard table (limit to 50 most recent)
                if len(packets) < 50:
                    packets.append({
                        "src": src,
                        "dst": dst,
                        "protocol": protocol,
                        "time": str(packet.sniff_time) if hasattr(packet, 'sniff_time') else "N/A"
                    })
                
                # Run all vulnerability checks
                scanInsecureProtocols(packet)
                checkPortProtocolMismatch(packet)
                checkVulnTls(packet)
                checkUnencryptedCreds(packet)
            except Exception:
                # Skip problematic packets
                continue
        
        # Close the capture
        capture.close()
        
        # ================= PREPARE RESULTS FOR FLASK =================
        # Calculate vulnerability total
        vulnTotal = (len(insecureProtocols) + len(portMismatches) + 
                     len(vulnTlsVersions) + len(unencryptedCreds))
        
        # Return data dictionary for Flask (matches dashboard.html template)
        return {
            "total_packets": totalPackets,
            "tcp_packets": tcp_packets,
            "udp_packets": udp_packets,
            "unique_ips": len(unique_ips),
            "packets": packets,
            "insecure_protocols": insecureProtocols,
            "protocol_counter": protocolCounter,
            "port_mismatches": portMismatches,
            "vuln_tls": vulnTlsVersions,
            "unencrypted_creds": unencryptedCreds,
            "vulnerability_total": vulnTotal
        }
        
    except FileNotFoundError:
        return {
            "error": "File not found",
            "total_packets": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "unique_ips": 0,
            "packets": [],
            "insecure_protocols": [],
            "protocol_counter": {},
            "port_mismatches": [],
            "vuln_tls": [],
            "unencrypted_creds": [],
            "vulnerability_total": 0
        }
    except Exception as e:
        return {
            "error": str(e),
            "total_packets": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "unique_ips": 0,
            "packets": [],
            "insecure_protocols": [],
            "protocol_counter": {},
            "port_mismatches": [],
            "vuln_tls": [],
            "unencrypted_creds": [],
            "vulnerability_total": 0
        }