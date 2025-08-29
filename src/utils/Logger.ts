import winston from 'winston';
import chalk from 'chalk';

export class Logger {
  private logger: winston.Logger;
  private context: string;

  constructor(context: string = 'default') {
    this.context = context;
    
    const palette = {
      info: chalk.cyan,
      warn: chalk.yellow,
      error: chalk.red,
      debug: chalk.gray,
      trace: chalk.magenta,
    } as const;
    
    const colorFn = (level: string) => palette[level as keyof typeof palette] ?? chalk.white;

    this.logger = winston.createLogger({
      level: process.env.LOG_LEVEL || 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.printf(({ timestamp, level, message, context, ...meta }) => {
          const color = colorFn(level);
          const metaStr = Object.keys(meta).length ? ` ${JSON.stringify(meta)}` : '';
          return `${color(`[${timestamp}] ${level.toUpperCase()}`)} ${chalk.white(`[${context || this.context}]`)} ${message}${metaStr}`;
        })
      ),
      transports: [
        new winston.transports.Console(),
        new winston.transports.File({ 
          filename: 'logs/error.log', 
          level: 'error' 
        }),
        new winston.transports.File({ 
          filename: 'logs/combined.log' 
        })
      ]
    });
  }

  info(message: string, meta?: any) {
    this.log('info', message, meta);
  }

  warn(message: string, meta?: any) {
    this.log('warn', message, meta);
  }

  error(message: string, error?: Error) {
    this.log('error', message, { error: error?.message, stack: error?.stack });
  }

  debug(message: string, meta?: any) {
    this.log('debug', message, meta);
  }

  trace(message: string, meta?: any) {
    this.log('trace', message, meta);
  }

  audit(message: string, meta?: any) {
    this.log('info', `[AUDIT] ${message}`, meta);
  }

  private log(level: string, message: string, meta?: any) {
    this.logger.log(level, message, { context: this.context, ...meta });
  }
}
