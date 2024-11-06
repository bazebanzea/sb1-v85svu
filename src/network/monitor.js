const pcap = require('pcap');
const EventEmitter = require('events');
const logger = require('../utils/logger');

class NetworkMonitor extends EventEmitter {
  constructor() {
    super();
    this.session = null;
  }

  start() {
    try {
      this.session = pcap.createSession('', 'ip proto \\tcp or \\udp');
      
      this.session.on('packet', (raw_packet) => {
        const packet = this.parsePacket(raw_packet);
        this.emit('packet', packet);
      });

      logger.info('Network monitoring started');
    } catch (error) {
      logger.error('Failed to start network monitoring:', error);
      throw error;
    }
  }

  parsePacket(raw_packet) {
    const packet = pcap.decode.packet(raw_packet);
    return {
      timestamp: new Date(),
      protocol: packet.link_type,
      length: packet.pcap_header.len,
      source: packet.payload?.shost,
      destination: packet.payload?.dhost,
      data: packet.payload
    };
  }

  stop() {
    if (this.session) {
      this.session.close();
      this.session = null;
      logger.info('Network monitoring stopped');
    }
  }
}

module.exports = { NetworkMonitor };