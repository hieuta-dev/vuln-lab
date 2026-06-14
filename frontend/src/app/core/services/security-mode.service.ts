// FILE: frontend/src/app/core/services/security-mode.service.ts
// PURPOSE: Holds the global security mode toggle; persists to localStorage
// SECURITY NOTE: Mode is sent as a header — never trust it server-side without middleware validation

import { Injectable, signal } from '@angular/core';
import { BehaviorSubject } from 'rxjs';

export type SecurityMode = 'vulnerable' | 'secure';
const STORAGE_KEY = 'vuln-lab-mode';

@Injectable({ providedIn: 'root' })
export class SecurityModeService {
  private _mode$ = new BehaviorSubject<SecurityMode>(
    (localStorage.getItem(STORAGE_KEY) as SecurityMode) ?? 'vulnerable'
  );

  readonly currentMode$ = this._mode$.asObservable();
  readonly currentMode = signal<SecurityMode>(this._mode$.value);

  toggle(): void {
    const next: SecurityMode = this._mode$.value === 'vulnerable' ? 'secure' : 'vulnerable';
    this._mode$.next(next);
    this.currentMode.set(next);
    localStorage.setItem(STORAGE_KEY, next);
  }

  setMode(mode: SecurityMode): void {
    this._mode$.next(mode);
    this.currentMode.set(mode);
    localStorage.setItem(STORAGE_KEY, mode);
  }
}
