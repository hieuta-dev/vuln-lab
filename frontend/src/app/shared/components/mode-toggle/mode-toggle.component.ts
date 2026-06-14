// FILE: frontend/src/app/shared/components/mode-toggle/mode-toggle.component.ts
// PURPOSE: Security mode slide toggle — Vulnerable (red) ↔ Secure (green)

import { Component, inject } from '@angular/core';
import { MatSlideToggleModule } from '@angular/material/slide-toggle';
import { AsyncPipe } from '@angular/common';
import { SecurityModeService } from '../../../core/services/security-mode.service';

@Component({
  selector: 'app-mode-toggle',
  standalone: true,
  imports: [MatSlideToggleModule, AsyncPipe],
  template: `
    <div class="mode-wrap">
      <span class="mode-label" [class.active]="(svc.currentMode$ | async) === 'vulnerable'" [class.mode-vuln]="true">
        Vulnerable
      </span>
      <mat-slide-toggle
        [checked]="(svc.currentMode$ | async) === 'secure'"
        (change)="svc.toggle()"
        class="mode-toggle-ctrl">
      </mat-slide-toggle>
      <span class="mode-label" [class.active]="(svc.currentMode$ | async) === 'secure'" [class.mode-secure]="true">
        Secure
      </span>
    </div>
  `,
  styles: [`
    .mode-wrap { display: flex; align-items: center; gap: 8px; }
    .mode-label { font-size: 12px; font-weight: 600; color: var(--text-secondary); transition: color 0.2s; }
    .mode-vuln.active  { color: var(--accent-danger); }
    .mode-secure.active { color: var(--accent-success); }

    /* Override Material toggle colors */
    ::ng-deep .mode-toggle-ctrl .mdc-switch--selected .mdc-switch__track::after { background-color: var(--accent-success) !important; }
    ::ng-deep .mode-toggle-ctrl .mdc-switch:not(.mdc-switch--selected) .mdc-switch__track::after { background-color: var(--accent-danger) !important; }
    ::ng-deep .mode-toggle-ctrl .mdc-switch:not(.mdc-switch--selected) .mdc-switch__track::before { background-color: rgba(239,68,68,.3) !important; }
    ::ng-deep .mode-toggle-ctrl .mdc-switch__handle::after { background-color: white !important; }
  `],
})
export class ModeToggleComponent {
  svc = inject(SecurityModeService);
}
