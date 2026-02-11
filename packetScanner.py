import pyshark
import sys

# Lists and dictionaries to store findings
insecureProtocols = []      # Stores detected insecure protocols 
portMismatches = []         # Stores deteted port/protocol mismatches 
vulnTlsVersions = []        # Stores detected vulnerable TLS versions 
unencryptedCreds= []        # Stores detected plain text cred protocols 

# Counters
protocolCounter = {}        # Tracks number of packets seen per protocol
totalPackets = 0            # Tracks total number of packets scanned


# Task 1: Scan for any known insecure protocols
def scanInsecureProtocols(packet):
    # List of insecure protocols to check for
    protocolsToCheck = ['ftp', 'telnet', 'ssl', 'http']
    
    for proto in protocolsToCheck:
        # Checks for protocol layer
        if hasattr(packet, proto):
            protoUpper = proto.upper()

            # Track eacch protocol only once in the results list
            if protoUpper not in insecureProtocols:
                insecureProtocols.append(protoUpper)
            # Count number of packets that use this protocol
            protocolCounter[protoUpper] = protocolCounter.get(protoUpper, 0) + 1


# Task 2: Check if common ports are used by correct protocols
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


# Task 4: Scanning for any unencrypted credentials
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

# Prints results in a neat and clean matter
def printResults():
    print(f"\n{'='*70}")
    print("SCAN RESULTS")
    print(f"{'='*70}")
    print(f"Total packets analyzed: {totalPackets}\n")
    
    # Task 1: Insecure Protocols
    print("TASK 1: Scanning for Insecure Protocols")
    print("-" * 70)
    if insecureProtocols:
        for proto in insecureProtocols:
            count = protocolCounter.get(proto, 0)
            print(f"-> {proto} -> Packets: {count}")
    else:
        print("No insecure protocols detected")
    
    # Task 2: Port Mismatches
    print(f"\nTASK 2: Scannning for Port/Protocols Mismatches")
    print("-" * 70)
    if portMismatches:
        for mismatch in portMismatches:
            print(f"-> {mismatch}")
    else:
        print("No port mismatches detected")
    
    # Task 3: Vulnerable TLS Versions
    print(f"\nTASK 3: Scanning for Vulnerable TLS Version ")
    print("-" * 70)
    if vulnTlsVersions:
        for version in vulnTlsVersions:
            print(f"-> {version} detected")
    else:
        print("No vulnerable TLS versions detected")
    
   # Task 4: Unencrypted Credentials
    print(f"\nTASK 4: Scanning for Unencrypted Credentials")
    print("-" * 70)
    if unencryptedCreds:
        for cred in unencryptedCreds:
            print(f"-> {cred}")
    else:
        print("No unencrypted credentials detected")

    # Summary
    vulnTotal = (len(insecureProtocols) + len(portMismatches) + len(vulnTlsVersions) + len(unencryptedCreds))
    
    print(f"\n{'='*70}")
    print(f"SUMMARY: {vulnTotal} vulnerability type(s) found")
    print(f"{'='*70}\n")


# Main function (runs everything)
def main():
    global totalPackets
    
    # Check if file name was given
    if len(sys.argv) < 2:
        print("\nHow to run: python vuln_scanner.py <pcap_file>")
        sys.exit(1)
    
    # Get the file name from command line argument
    fileName = sys.argv[1]
    
    print(f"\n{'='*70}")
    print(f"Scanning: {fileName}")
    print(f"{'='*70}")
    
    try:
        # Open the file using pyshark.FileCapture
        capture = pyshark.FileCapture(fileName)
        
        # Loop through each packet in the capture
        print("Processing packets...", end='')
        for packet in capture:
            totalPackets += 1
            
            # Run all vulnerability checks
            scanInsecureProtocols(packet)
            checkPortProtocolMismatch(packet)
            checkVulnTls(packet)
            checkUnencryptedCreds(packet)
            
        
        # Close the capture
        capture.close()
        print(" Scan Finished!")
        
        # Print results
        printResults()
        
    # Error Checks
    except FileNotFoundError:
        print(f"\nERROR: File not found")
        sys.exit(1)
    except Exception as e:
        print(f"\nERROR: {e}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()