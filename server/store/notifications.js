import Database from 'better-sqlite3'
import { randomUUID } from 'crypto'

export class NotificationQueue {
  constructor(dbPath) {
    this.dbPath = dbPath || ':memory:'
    this.db = new Database(this.dbPath)
    this.db.pragma('journal_mode = WAL')
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS notifications (
        id TEXT PRIMARY KEY,
        user_addr TEXT NOT NULL,
        type TEXT NOT NULL,
        from_addr TEXT,
        data TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_notif_user ON notifications(user_addr);
      CREATE INDEX IF NOT EXISTS idx_notif_from ON notifications(user_addr, from_addr, type);
    `)
  }

  async push(userAddr, notification, opts = {}) {
    notification.id = randomUUID()

    // Deduplicate: if opts.deduplicateBy is set, remove existing notifications
    // of the same type from the same sender
    if (opts.deduplicateBy === 'from' && notification.from) {
      this.db.prepare(
        'DELETE FROM notifications WHERE user_addr = ? AND from_addr = ? AND type = ?'
      ).run(userAddr, notification.from, notification.type)
    }

    this.db.prepare(
      'INSERT INTO notifications (id, user_addr, type, from_addr, data, created_at) VALUES (?, ?, ?, ?, ?, ?)'
    ).run(
      notification.id,
      userAddr,
      notification.type,
      notification.from || null,
      JSON.stringify(notification),
      Date.now()
    )

    // Keep max 100 per user
    const count = this.db.prepare('SELECT COUNT(*) as c FROM notifications WHERE user_addr = ?').get(userAddr).c
    if (count > 100) {
      this.db.prepare(
        'DELETE FROM notifications WHERE id IN (SELECT id FROM notifications WHERE user_addr = ? ORDER BY created_at ASC LIMIT ?)'
      ).run(userAddr, count - 100)
    }
  }

  async getAll(userAddr) {
    const rows = this.db.prepare(
      'SELECT data FROM notifications WHERE user_addr = ? ORDER BY created_at ASC'
    ).all(userAddr)
    return rows.map(r => JSON.parse(r.data))
  }

  async remove(userAddr, id) {
    this.db.prepare('DELETE FROM notifications WHERE user_addr = ? AND id = ?').run(userAddr, id)
  }
}
