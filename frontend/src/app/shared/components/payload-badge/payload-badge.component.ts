// FILE: frontend/src/app/shared/components/payload-badge/payload-badge.component.ts
// PURPOSE: Displays a payload string with a copy-to-clipboard button

import { Component, Input, signal } from '@angular/core';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatTooltipModule } from '@angular/material/tooltip';

@Component({
  selector: 'app-payload-badge',
  standalone: true,
  imports: [MatIconModule, MatButtonModule, MatTooltipModule],
  template: `
    <span class="badge">
      <code class="payload-text">{{ payload }}</code>
      <button mat-icon-button matTooltip="Copy" (click)="copy()">
        <mat-icon>content_copy</mat-icon>
      </button>
      @if (copied()) { <span class="copied">Copied!</span> }
    </span>
  `,
  styles: [`
    .badge { display: inline-flex; align-items: center; background: #1e1e2e;
             border-radius: 4px; padding: 2px 8px; gap: 4px; }
    .payload-text { color: #f38ba8; font-size: 12px; word-break: break-all; }
    .copied { font-size: 11px; color: #a6e3a1; }
    button { transform: scale(0.7); }
  `],
})
export class PayloadBadgeComponent {
  @Input() payload = '';
  copied = signal(false);

  copy(): void {
    navigator.clipboard.writeText(this.payload).then(() => {
      this.copied.set(true);
      setTimeout(() => this.copied.set(false), 1500);
    });
  }
}
