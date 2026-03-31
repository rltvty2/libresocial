import 'dotenv/config'
import { existsSync, mkdirSync } from 'fs'

export const config = {
  port: parseInt(process.env.PORT || '3000'),
  host: process.env.HOST || '0.0.0.0',
  domain: process.env.DOMAIN || 'localhost',

  dataDir: process.env.DATA_DIR || './data',

  db: {
    path: process.env.DB_PATH || './data/friendsforum.db',
  },

  userQuotaBytes: 0, // 0 = unlimited

  rateLimit: {
    windowMs: 15 * 60 * 1000,
    max: 3000,
  },
}

if (!existsSync(config.dataDir)) mkdirSync(config.dataDir, { recursive: true })
