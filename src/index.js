const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const { NetworkMonitor } = require('./network/monitor');
const { ThreatDetector } = require('./ml/detector');
const logger = require('./utils/logger');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

const monitor = new NetworkMonitor();
const detector = new ThreatDetector();

// WebSocket connection for real-time updates
io.on('connection', (socket) => {
  logger.info('Client connected');
  
  socket.on('disconnect', () => {
    logger.info('Client disconnected');
  });
});

// Start monitoring and analysis
monitor.on('packet', async (packet) => {
  try {
    const threat = await detector.analyzePacket(packet);
    if (threat.score > 0.7) {
      logger.warn(`Potential threat detected: ${threat.type}`);
      io.emit('threat-alert', threat);
    }
  } catch (error) {
    logger.error('Error analyzing packet:', error);
  }
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  logger.info(`IoT Security Monitor running on port ${PORT}`);
  monitor.start();
});