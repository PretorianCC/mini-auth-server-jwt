const pino = require('pino');

export const logger = pino(
  {
    level: 'info',
    timestamp: pino.stdTimeFunctions.isoTime,
  },
  pino.destination('./logs/app.log')
);

// logger.error('Database connection failed');
// logger.warn('High memory usage detected');
// logger.info('User authentication successful');
// logger.debug('Processing user preferences'); // Completely skipped, no overhead
