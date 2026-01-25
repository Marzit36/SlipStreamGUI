// TUN/TAP support - requires native module
// TUN mode requires a native Node.js module that needs to be compiled
// Available options:
// 1. node-tuntap (old, requires manual build)
// 2. node-tuntap2 (GitHub only, requires compilation)
// 3. Manual installation from source
let tuntap;
try {
  // Try node-tuntap2 first
  tuntap = require('node-tuntap2');
} catch (err) {
  try {
    // Fallback to node-tuntap
    tuntap = require('node-tuntap');
  } catch (err2) {
    console.error('TUN/TAP module not available:', err2.message);
    tuntap = null;
  }
}

const { SocksClient } = require('socks');
const ip = require('ip');
const net = require('net');
const dns = require('dns').promises;

const SOCKS5_PORT = 5201;
const TUN_IP = '10.0.0.1';
const TUN_NETMASK = '255.255.255.0';
const TUN_MTU = 1500;

let tunInterface = null;
let isRunning = false;

// DNS cache
const dnsCache = new Map();

// Active connections
const activeConnections = new Map();

function createTunInterface() {
  return new Promise((resolve, reject) => {
    if (!tuntap) {
      reject(new Error('TUN mode is not available. Please install node-tuntap2: npm install node-tuntap2. Note: This requires native compilation and admin privileges.'));
      return;
    }
    
    try {
      const platform = process.platform;
      const tunName = platform === 'darwin' ? 'tun0' : 'tun0';
      
      tunInterface = tuntap({
        type: 'tun',
        name: tunName,
        mtu: TUN_MTU,
        addr: TUN_IP,
        mask: TUN_NETMASK,
        persist: false,
        up: true,
        running: true
      });

      console.log(`TUN interface ${tunName} created`);

      // Handle incoming packets
      tunInterface.on('data', (packet) => {
        handleTunPacket(packet);
      });

      tunInterface.on('error', (err) => {
        console.error('TUN interface error:', err);
        if (isRunning) {
          // Try to recreate
          setTimeout(() => {
            if (isRunning) {
              createTunInterface().catch(console.error);
            }
          }, 1000);
        }
      });

      resolve(tunInterface);
    } catch (err) {
      reject(err);
    }
  });
}

function parseIPPacket(packet) {
  if (packet.length < 20) {
    return null; // Invalid IP packet
  }

  const version = (packet[0] >> 4) & 0x0F;
  if (version !== 4) {
    return null; // Only IPv4 for now
  }

  const headerLength = (packet[0] & 0x0F) * 4;
  const protocol = packet[9];
  const srcIP = `${packet[12]}.${packet[13]}.${packet[14]}.${packet[15]}`;
  const dstIP = `${packet[16]}.${packet[17]}.${packet[18]}.${packet[19]}`;

  // Extract ports for TCP/UDP
  let srcPort = 0;
  let dstPort = 0;
  
  if (protocol === 6) { // TCP
    if (packet.length >= headerLength + 4) {
      srcPort = (packet[headerLength] << 8) | packet[headerLength + 1];
      dstPort = (packet[headerLength + 2] << 8) | packet[headerLength + 3];
    }
  } else if (protocol === 17) { // UDP
    if (packet.length >= headerLength + 4) {
      srcPort = (packet[headerLength] << 8) | packet[headerLength + 1];
      dstPort = (packet[headerLength + 2] << 8) | packet[headerLength + 3];
    }
  }

  return {
    version,
    protocol,
    srcIP,
    dstIP,
    srcPort,
    dstPort,
    headerLength,
    payload: packet.slice(headerLength)
  };
}

async function resolveHostname(ip) {
  // Check if it's already an IP
  if (ip.match(/^\d+\.\d+\.\d+\.\d+$/)) {
    return ip;
  }

  // Check cache
  if (dnsCache.has(ip)) {
    return dnsCache.get(ip);
  }

  try {
    const addresses = await dns.resolve4(ip);
    const resolvedIP = addresses[0];
    dnsCache.set(ip, resolvedIP);
    return resolvedIP;
  } catch (err) {
    console.error(`DNS resolution failed for ${ip}:`, err);
    return ip; // Return as-is, might be IP already
  }
}

async function handleTunPacket(packet) {
  const ipPacket = parseIPPacket(packet);
  if (!ipPacket) {
    return; // Invalid packet
  }

  // Skip packets from our TUN interface
  if (ipPacket.srcIP === TUN_IP) {
    return;
  }

  // Only handle TCP for now (UDP is more complex)
  if (ipPacket.protocol !== 6) {
    return;
  }

  const connectionKey = `${ipPacket.srcIP}:${ipPacket.srcPort}-${ipPacket.dstIP}:${ipPacket.dstPort}`;

  // Resolve destination IP (in case it's a hostname)
  const dstIP = await resolveHostname(ipPacket.dstIP);

  // Forward through SOCKS5
  forwardThroughSocks5(ipPacket, dstIP, connectionKey);
}

function forwardThroughSocks5(ipPacket, dstIP, connectionKey) {
  // Check if connection already exists
  if (activeConnections.has(connectionKey)) {
    const conn = activeConnections.get(connectionKey);
    // Forward data through existing connection
    if (conn.socket && !conn.socket.destroyed) {
      // This is simplified - in reality we need to handle TCP state machine
      return;
    }
  }

  // Create new SOCKS5 connection
  SocksClient.createConnection({
    proxy: {
      host: '127.0.0.1',
      port: SOCKS5_PORT,
      type: 5
    },
    command: 'connect',
    destination: {
      host: dstIP,
      port: ipPacket.dstPort
    }
  }).then((info) => {
    const socket = info.socket;
    activeConnections.set(connectionKey, { socket, ipPacket });

    // Handle data from SOCKS5
    socket.on('data', (data) => {
      // Create response IP packet and send back through TUN
      // This is simplified - need proper IP packet construction
      sendResponseThroughTun(ipPacket, data);
    });

    socket.on('close', () => {
      activeConnections.delete(connectionKey);
    });

    socket.on('error', (err) => {
      console.error('SOCKS5 connection error:', err);
      activeConnections.delete(connectionKey);
    });

    // Send initial data if any
    if (ipPacket.payload && ipPacket.payload.length > 0) {
      socket.write(ipPacket.payload);
    }
  }).catch((err) => {
    console.error('Failed to create SOCKS5 connection:', err);
  });
}

function sendResponseThroughTun(originalPacket, data) {
  // This is a simplified version
  // In reality, we need to construct a proper IP packet with:
  // - Swapped source/destination IPs
  // - Updated checksums
  // - Proper TCP headers
  // For now, this is a placeholder
  if (tunInterface) {
    // Construct response packet (simplified)
    // This would need proper IP/TCP packet construction
    console.log('Would send response packet through TUN');
  }
}

async function configureRouting() {
  const platform = process.platform;
  const { exec } = require('child_process');
  const { promisify } = require('util');
  const execAsync = promisify(exec);

  try {
    if (platform === 'darwin') {
      // macOS: Add route for TUN interface
      // Route all traffic through TUN (except TUN subnet)
      await execAsync(`route add -net 0.0.0.0/1 ${TUN_IP}`);
      await execAsync(`route add -net 128.0.0.0/1 ${TUN_IP}`);
      console.log('Routing configured on macOS');
    } else if (platform === 'win32') {
      // Windows: Add route
      await execAsync(`route add 0.0.0.0 mask 0.0.0.0 ${TUN_IP} metric 1`);
      console.log('Routing configured on Windows');
    }
    return true;
  } catch (err) {
    console.error('Failed to configure routing:', err);
    return false;
  }
}

async function removeRouting() {
  const platform = process.platform;
  const { exec } = require('child_process');
  const { promisify } = require('util');
  const execAsync = promisify(exec);

  try {
    if (platform === 'darwin') {
      await execAsync(`route delete -net 0.0.0.0/1 ${TUN_IP}`).catch(() => {});
      await execAsync(`route delete -net 128.0.0.0/1 ${TUN_IP}`).catch(() => {});
    } else if (platform === 'win32') {
      await execAsync(`route delete 0.0.0.0 mask 0.0.0.0 ${TUN_IP}`).catch(() => {});
    }
    return true;
  } catch (err) {
    console.error('Failed to remove routing:', err);
    return false;
  }
}

async function startTunMode() {
  if (isRunning) {
    return { success: false, message: 'TUN mode is already running' };
  }

  try {
    // Create TUN interface
    await createTunInterface();
    
    // Configure routing
    const routingConfigured = await configureRouting();
    
    isRunning = true;
    
    return {
      success: true,
      message: routingConfigured 
        ? 'TUN mode started successfully' 
        : 'TUN mode started but routing configuration failed',
      details: {
        tunRunning: true,
        routingConfigured
      }
    };
  } catch (err) {
    return { success: false, message: err.message };
  }
}

function stopTunMode() {
  isRunning = false;
  
  // Close all active connections
  for (const [key, conn] of activeConnections.entries()) {
    if (conn.socket && !conn.socket.destroyed) {
      conn.socket.destroy();
    }
  }
  activeConnections.clear();
  
  // Remove routing
  removeRouting().catch(console.error);
  
  // Close TUN interface
  if (tunInterface) {
    try {
      tunInterface.destroy();
    } catch (err) {
      console.error('Error closing TUN interface:', err);
    }
    tunInterface = null;
  }
  
  return {
    success: true,
    message: 'TUN mode stopped',
    details: {
      tunRunning: false,
      routingConfigured: false
    }
  };
}

function getTunStatus() {
  return {
    isRunning,
    tunInterface: tunInterface !== null,
    activeConnections: activeConnections.size
  };
}

module.exports = {
  startTunMode,
  stopTunMode,
  getTunStatus
};
