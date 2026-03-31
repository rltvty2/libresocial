import { randomBytes } from 'crypto'

export class SessionStore {
  constructor(opts = {}) {
    this.sessions = new Map()
    this.challenges = new Map()
    this.ttl = opts.ttl || 7 * 24 * 60 * 60 * 1000
    this._pruneInterval = setInterval(() => this._prune(), 3600000)
  }

  create(user) {
    const token = randomBytes(32).toString('hex')
    this.sessions.set(token, { user, createdAt: Date.now(), expiresAt: Date.now() + this.ttl })
    return token
  }

  get(token) {
    const s = this.sessions.get(token)
    if (!s) return null
    if (Date.now() > s.expiresAt) { this.sessions.delete(token); return null }
    return s
  }

  destroy(token) { this.sessions.delete(token) }

  storeChallenge(username, nonce) {
    this.challenges.set(username, { nonce, expiresAt: Date.now() + 300000 })
  }

  getChallenge(username) {
    const ch = this.challenges.get(username)
    if (!ch) return null
    if (Date.now() > ch.expiresAt) { this.challenges.delete(username); return null }
    return ch.nonce
  }

  clearChallenge(username) { this.challenges.delete(username) }

  _prune() {
    const now = Date.now()
    for (const [t, s] of this.sessions) { if (now > s.expiresAt) this.sessions.delete(t) }
    for (const [u, c] of this.challenges) { if (now > c.expiresAt) this.challenges.delete(u) }
  }

  close() { clearInterval(this._pruneInterval) }
}
