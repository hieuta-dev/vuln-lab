// FILE: frontend/src/app/shared/components/source-viewer/source-viewer.component.ts
// PURPOSE: Side-by-side syntax-highlighted code diff — Vulnerable vs Secure tabs

import { Component, Input, OnChanges, inject } from '@angular/core';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';
import * as Prism from 'prismjs';
import 'prismjs/components/prism-python';
import 'prismjs/components/prism-javascript';
import { MatTabsModule } from '@angular/material/tabs';

@Component({
  selector: 'app-source-viewer',
  standalone: true,
  imports: [MatTabsModule],
  template: `
    <div class="viewer-wrap">
      <mat-tab-group>
        <mat-tab>
          <ng-template mat-tab-label>
            <span class="tab-label tab-vuln">⚠ Vulnerable</span>
          </ng-template>
          <pre class="code-block code-vuln"><code [innerHTML]="highlightedVuln"></code></pre>
        </mat-tab>
        <mat-tab>
          <ng-template mat-tab-label>
            <span class="tab-label tab-secure">✓ Secure</span>
          </ng-template>
          <pre class="code-block code-secure"><code [innerHTML]="highlightedSecure"></code></pre>
        </mat-tab>
      </mat-tab-group>
    </div>
  `,
  styles: [`
    .viewer-wrap { border: 1px solid var(--border); border-radius: var(--radius-md); overflow: hidden; }
    .code-block {
      margin: 0; padding: 20px; overflow-x: auto;
      font-size: 13px; line-height: 1.6; min-height: 80px;
      background: #0d0d14; border-radius: 0;
      font-family: 'JetBrains Mono', 'Fira Code', monospace;
    }
    .code-vuln   { border-top: 2px solid var(--accent-danger); }
    .code-secure { border-top: 2px solid var(--accent-success); }
    .tab-vuln    { color: var(--accent-danger); font-weight: 600; }
    .tab-secure  { color: var(--accent-success); font-weight: 600; }
  `],
})
export class SourceViewerComponent implements OnChanges {
  @Input() vulnerable = '';
  @Input() secure = '';

  highlightedVuln: SafeHtml = '';
  highlightedSecure: SafeHtml = '';

  private sanitizer = inject(DomSanitizer);

  ngOnChanges(): void {
    const lang = Prism.languages['python'] ?? Prism.languages['javascript'];
    this.highlightedVuln = this.sanitizer.bypassSecurityTrustHtml(
      Prism.highlight(this.vulnerable, lang, 'python')
    );
    this.highlightedSecure = this.sanitizer.bypassSecurityTrustHtml(
      Prism.highlight(this.secure, lang, 'python')
    );
  }
}
