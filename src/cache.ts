/**
 * Minimaler In-Memory-TTL-Cache fuer die entschluesselten Admin-Daten.
 *
 * Zweck: Nicht bei jedem Login/Request die GitHub-API aufrufen (Latenz +
 * Rate-Limit). Bei Schreibvorgaengen wird der Cache sofort invalidiert, damit
 * kein Prozess laenger als noetig veraltete Daten sieht.
 *
 * Failover: Wenn ein Refresh fehlschlaegt (GitHub nicht erreichbar), liefert
 * getStaleIfAvailable() den letzten bekannten Stand zurueck, statt die App
 * komplett lahmzulegen (siehe Phase 4 / Fallback im Ursprungsplan). Der
 * Aufrufer entscheidet bewusst, ob er diesen Fallback nutzen will.
 */
export class TtlCache<T> {
  private value: T | undefined;
  private fetchedAtMs = 0;
  private readonly ttlMs: number;
  private readonly staleMaxAgeMs: number;

  constructor(ttlMs: number, staleMaxAgeMs = ttlMs * 20) {
    this.ttlMs = ttlMs;
    this.staleMaxAgeMs = staleMaxAgeMs;
  }

  get(): T | undefined {
    if (this.value === undefined) return undefined;
    if (Date.now() - this.fetchedAtMs > this.ttlMs) return undefined;
    return this.value;
  }

  getStaleIfAvailable(): { value: T; ageMs: number } | undefined {
    if (this.value === undefined) return undefined;
    const ageMs = Date.now() - this.fetchedAtMs;
    if (ageMs > this.staleMaxAgeMs) return undefined;
    return { value: this.value, ageMs };
  }

  set(value: T): void {
    this.value = value;
    this.fetchedAtMs = Date.now();
  }

  invalidate(): void {
    this.value = undefined;
    this.fetchedAtMs = 0;
  }
}
