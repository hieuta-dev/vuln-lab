// FILE: frontend/src/app/app.component.ts
// PURPOSE: Root bootstrap — shows 800ms loader then renders the routed layout

import { Component, OnInit, signal } from '@angular/core';
import { RouterOutlet } from '@angular/router';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [RouterOutlet, MatProgressSpinnerModule],
  template: `
    @if (loading()) {
      <div class="app-loader">
        <div class="loader-content">
          <span class="loader-logo">🛡️</span>
          <h1 class="loader-title">VulnLab</h1>
          <p class="loader-sub">Security Training Platform</p>
          <mat-spinner diameter="28" class="loader-spinner"></mat-spinner>
        </div>
      </div>
    } @else {
      <router-outlet />
    }
  `,
  styles: [`
    .app-loader {
      position: fixed; inset: 0;
      background: var(--bg-primary);
      display: flex; align-items: center; justify-content: center;
      z-index: 9999;
    }
    .loader-content {
      display: flex; flex-direction: column; align-items: center; gap: 8px;
      animation: fadeIn 0.3s ease;
    }
    .loader-logo  { font-size: 48px; line-height: 1; }
    .loader-title { font-size: 28px; font-weight: 800; color: var(--accent-light); margin: 0; }
    .loader-sub   { font-size: 13px; color: var(--text-secondary); margin: 0 0 16px; }
    .loader-spinner { --mdc-circular-progress-active-indicator-color: var(--accent) !important; }
  `],
})
export class AppComponent implements OnInit {
  loading = signal(true);

  ngOnInit(): void {
    setTimeout(() => this.loading.set(false), 800);
  }
}
