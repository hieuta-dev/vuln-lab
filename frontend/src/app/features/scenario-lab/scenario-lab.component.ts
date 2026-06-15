// FILE: frontend/src/app/features/scenario-lab/scenario-lab.component.ts
// PURPOSE: AI-powered scenario generator — calls backend agent, renders structured lab guide

import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute } from '@angular/router';
import { finalize } from 'rxjs';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatSelectModule } from '@angular/material/select';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatChipsModule } from '@angular/material/chips';
import { MatExpansionModule } from '@angular/material/expansion';
import { MatIconModule } from '@angular/material/icon';
import { MatTooltipModule } from '@angular/material/tooltip';
import { ScenarioService, Scenario, VulnType } from '../../core/services/scenario.service';
import { SourceViewerComponent } from '../../shared/components/source-viewer/source-viewer.component';

// Placeholder strings the AI sometimes returns instead of real payloads
const PLACEHOLDER_PAYLOADS = new Set([
  'example payload string', 'exploit payload', 'payload string',
  'your payload here', 'insert payload', 'see documentation',
  'see owasp docs', 'enter payload here', '',
]);

// Phase → color mapping
const PHASE_COLORS: Record<string, string> = {
  reconnaissance: 'var(--accent)',
  probe:          '#06b6d4',
  exploit:        'var(--accent-danger)',
  impact:         '#dc2626',
  observe:        'var(--accent-warning)',
  verify:         '#a855f7',
  defense:        'var(--accent-success)',
  remediation:    'var(--accent-success)',
};

@Component({
  selector: 'app-scenario-lab',
  standalone: true,
  imports: [
    FormsModule, MatFormFieldModule, MatSelectModule, MatButtonModule,
    MatCardModule, MatProgressSpinnerModule, MatChipsModule, MatExpansionModule,
    MatIconModule, MatTooltipModule, SourceViewerComponent,
  ],
  template: `
    <div class="fade-in">
      <h2>AI Scenario Lab</h2>
      <p>Select a vulnerability type and difficulty, then generate a structured attack scenario
         using local AI (Ollama / llama3.2).</p>

      <!-- Controls -->
      <div class="controls">
        <mat-form-field appearance="outline">
          <mat-label>Vulnerability Type</mat-label>
          <mat-select [(ngModel)]="selectedType">
            @for (v of svc.VULN_TYPES; track v.id) {
              <mat-option [value]="v.id">{{ v.label }}</mat-option>
            }
          </mat-select>
        </mat-form-field>

        <mat-form-field appearance="outline">
          <mat-label>Difficulty</mat-label>
          <mat-select [(ngModel)]="difficulty">
            <mat-option value="beginner">Beginner</mat-option>
            <mat-option value="intermediate">Intermediate</mat-option>
            <mat-option value="advanced">Advanced</mat-option>
          </mat-select>
        </mat-form-field>

        <button mat-raised-button color="primary" (click)="generate()" [disabled]="loading()">
          @if (loading()) {
            <mat-spinner diameter="18" style="display:inline-block;margin-right:8px"></mat-spinner>
            Generating…
          } @else {
            <mat-icon>auto_awesome</mat-icon> Generate Scenario
          }
        </button>
      </div>

      <!-- Loading state -->
      @if (loading()) {
        <div class="loading-state">
          <mat-spinner diameter="36"></mat-spinner>
          <div>
            <strong>Generating with AI…</strong>
            <p>Ollama is building your scenario — this takes 15–45 seconds on first run.</p>
          </div>
        </div>
      }

      <!-- Error state -->
      @if (errorMessage()) {
        <div class="error-card">
          <mat-icon>error_outline</mat-icon>
          <div>
            <strong>Generation failed</strong>
            <p>{{ errorMessage() }}</p>
            <p class="error-hint">
              Make sure Ollama is running: <code>ollama serve</code> &amp;
              model is pulled: <code>ollama pull llama3.2</code>
            </p>
          </div>
        </div>
      }

      <!-- Result -->
      @if (scenario()) {
        <div class="scenario-result fade-in">
          <!-- Header -->
          <div class="scenario-header">
            <h3>{{ scenario()!.title }}</h3>
            <div class="scenario-meta">
              <span [class]="'sev-badge sev-' + (scenario()!.risk?.severity?.toLowerCase() ?? 'info')">
                CVSS {{ scenario()!.risk?.cvss_score }} — {{ scenario()!.risk?.severity }}
              </span>
              <span class="owasp-tag">{{ scenario()!.risk?.owasp_category }}</span>
            </div>
          </div>
          <p class="scenario-desc">{{ scenario()!.description }}</p>

          <!-- Attack Steps -->
          <mat-expansion-panel [expanded]="true">
            <mat-expansion-panel-header>
              <mat-panel-title>⚔ Attack Steps</mat-panel-title>
            </mat-expansion-panel-header>
            @if (scenario()!.steps?.length) {
              @for (s of scenario()!.steps; track s.step) {
                <div class="step" [style.border-left-color]="phaseColor(s.phase)">
                  <div class="step-header">
                    <span class="step-num" [style.background]="phaseColor(s.phase)">{{ s.step }}</span>
                    <span class="step-phase" [style.color]="phaseColor(s.phase)">{{ s.phase }}</span>
                    <strong>{{ s.title }}</strong>
                  </div>
                  <p>{{ s.description }}</p>
                  <!-- Only show payload code block if it's a real payload, not a placeholder -->
                  @if (s.payload && !isPlaceholder(s.payload)) {
                    <div class="payload-code-block">
                      <div class="payload-code-header">
                        <span class="payload-label">Payload</span>
                        <button class="copy-btn" (click)="copy(s.payload, $event)" matTooltip="Copy payload">
                          <mat-icon>content_copy</mat-icon>
                        </button>
                      </div>
                      <pre class="payload-pre"><code>{{ s.payload }}</code></pre>
                    </div>
                  }
                </div>
              }
            } @else {
              <p class="empty-msg">No steps available.</p>
            }
          </mat-expansion-panel>

          <!-- Payloads -->
          <mat-expansion-panel>
            <mat-expansion-panel-header>
              <mat-panel-title>💣 Payloads</mat-panel-title>
            </mat-expansion-panel-header>
            @if (realPayloads().length) {
              @for (p of realPayloads(); track p.payload) {
                <div class="payload-card">
                  <!-- Copy button row -->
                  <div class="payload-card-header">
                    <span class="payload-type-label">PAYLOAD</span>
                    <button class="copy-btn" (click)="copy(p.payload, $event)" matTooltip="Copy to clipboard">
                      <mat-icon>content_copy</mat-icon>
                      <span>Copy</span>
                    </button>
                  </div>
                  <!-- Code block -->
                  <pre class="payload-pre payload-pre--card"><code>{{ p.payload }}</code></pre>
                  <!-- Description -->
                  <p class="payload-desc"><em>{{ p.description }}</em></p>
                  @if (p.expected_outcome) {
                    <p class="payload-expected">
                      <span class="expected-label">Expected:</span> {{ p.expected_outcome }}
                    </p>
                  }
                </div>
              }
            } @else {
              <p class="empty-msg">No payloads available for this scenario.</p>
            }
          </mat-expansion-panel>

          <!-- Defense Tips -->
          <mat-expansion-panel>
            <mat-expansion-panel-header>
              <mat-panel-title>🛡 Defense Tips</mat-panel-title>
            </mat-expansion-panel-header>
            @if (scenario()!.defense_tips?.length) {
              <ul class="tips-list">
                @for (t of scenario()!.defense_tips; track t) { <li>{{ t }}</li> }
              </ul>
            } @else {
              <p class="empty-msg">No defense tips available.</p>
            }
          </mat-expansion-panel>

          <!-- Code Examples -->
          @if (hasRealCode()) {
            <mat-expansion-panel>
              <mat-expansion-panel-header>
                <mat-panel-title>📄 Code Examples</mat-panel-title>
              </mat-expansion-panel-header>
              <app-source-viewer
                [vulnerable]="scenario()!.code_examples.vulnerable"
                [secure]="scenario()!.code_examples.secure" />
            </mat-expansion-panel>
          }
        </div>
      }
    </div>
  `,
  styles: [`
    h2 { margin-bottom: 4px; }
    .controls { display: flex; gap: 16px; flex-wrap: wrap; align-items: center; margin: 16px 0; }
    mat-form-field { min-width: 220px; }

    .loading-state {
      display: flex; align-items: center; gap: 16px;
      background: var(--bg-surface); border: 1px solid var(--border);
      border-radius: var(--radius-lg); padding: 20px; margin: 16px 0;
    }
    .loading-state strong { color: var(--text-primary); }
    .loading-state p { margin: 4px 0 0; font-size: 13px; }

    .error-card {
      display: flex; align-items: flex-start; gap: 12px;
      background: rgba(239,68,68,.08); border: 1px solid rgba(239,68,68,.3);
      border-radius: var(--radius-lg); padding: 16px; margin: 16px 0;
      color: var(--accent-danger);
    }
    .error-card mat-icon { margin-top: 2px; flex-shrink: 0; }
    .error-card strong { display: block; margin-bottom: 4px; }
    .error-card p { margin: 2px 0; font-size: 13px; color: var(--text-secondary); }
    .error-hint { font-size: 12px !important; color: var(--text-secondary) !important; }
    .error-hint code { font-size: 12px; }

    .scenario-result { margin-top: 20px; }
    .scenario-header { margin-bottom: 12px; }
    .scenario-header h3 { margin: 0 0 8px; font-size: 1.3rem; color: var(--text-primary); }
    .scenario-meta { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }

    .sev-badge { padding: 3px 10px; border-radius: var(--radius-xl); font-size: 11px; font-weight: 700; }
    .sev-critical { background: rgba(239,68,68,.15); color: #ef4444; }
    .sev-high     { background: rgba(249,115,22,.15); color: #f97316; }
    .sev-medium   { background: rgba(234,179,8,.15);  color: #eab308; }
    .sev-low      { background: rgba(34,197,94,.15);  color: #22c55e; }
    .sev-info     { background: rgba(100,116,139,.15); color: #94a3b8; }

    .owasp-tag { font-size: 12px; color: var(--text-secondary); }
    .scenario-desc { color: var(--text-secondary); margin-bottom: 12px; }

    mat-expansion-panel { margin-bottom: 8px; }

    /* ── Attack steps ───────────────────────────────────────────────────── */
    .step {
      margin: 12px 0; padding: 10px 12px;
      border-left: 3px solid var(--accent);
      background: var(--bg-elevated);
      border-radius: 0 var(--radius-sm) var(--radius-sm) 0;
    }
    .step-header { display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }
    .step-num {
      background: var(--accent); color: white;
      width: 22px; height: 22px; border-radius: 50%;
      display: flex; align-items: center; justify-content: center;
      font-size: 11px; font-weight: 700; flex-shrink: 0;
    }
    .step-phase { font-size: 10px; font-weight: 700; text-transform: uppercase; }
    .step > p { margin: 4px 0 8px; font-size: 13px; color: var(--text-secondary); }

    /* ── Payload code block inside steps ────────────────────────────────── */
    .payload-code-block {
      background: #0d0d14; border: 1px solid var(--border);
      border-radius: var(--radius-md); overflow: hidden; margin-top: 6px;
    }
    .payload-code-header {
      display: flex; align-items: center; justify-content: space-between;
      padding: 4px 10px; background: rgba(124,58,237,.12);
      border-bottom: 1px solid var(--border);
    }
    .payload-label { font-size: 10px; font-weight: 700; color: var(--accent-light); letter-spacing: .08em; text-transform: uppercase; }
    .payload-pre {
      margin: 0; padding: 10px 14px; overflow-x: auto;
      font-family: 'JetBrains Mono','Fira Code',monospace;
      font-size: 12px; color: var(--accent-light); line-height: 1.5;
      white-space: pre-wrap; word-break: break-all; background: transparent;
    }

    /* ── Payload cards (in Payloads panel) ─────────────────────────────── */
    .payload-card {
      background: var(--bg-surface); border: 1px solid var(--border);
      border-radius: var(--radius-md); margin: 10px 0; overflow: hidden;
    }
    .payload-card-header {
      display: flex; align-items: center; justify-content: space-between;
      padding: 6px 12px; background: rgba(124,58,237,.08);
      border-bottom: 1px solid var(--border);
    }
    .payload-type-label { font-size: 10px; font-weight: 700; color: var(--accent-light); letter-spacing: .08em; text-transform: uppercase; }
    .payload-pre--card {
      background: #0d0d14; border: none; border-radius: 0;
      padding: 12px 14px; margin: 0;
    }
    .payload-desc { font-size: 13px; color: var(--text-secondary); margin: 6px 12px 2px; font-style: italic; }
    .payload-expected { font-size: 12px; color: var(--text-secondary); margin: 2px 12px 10px; }
    .expected-label { font-weight: 600; color: var(--text-primary); }

    /* ── Copy button ─────────────────────────────────────────────────────── */
    .copy-btn {
      display: inline-flex; align-items: center; gap: 4px;
      background: none; border: none; color: var(--text-secondary);
      cursor: pointer; font-family: inherit; font-size: 12px;
      padding: 2px 6px; border-radius: var(--radius-sm);
      transition: color .15s;
    }
    .copy-btn:hover { color: var(--accent-light); }
    .copy-btn mat-icon { font-size: 14px; width: 14px; height: 14px; }
    .copy-btn.copied { color: var(--accent-success); }

    /* ── Misc ──────────────────────────────────────────────────────────── */
    .tips-list { margin: 0; padding-left: 20px; }
    .tips-list li { font-size: 13px; margin-bottom: 6px; color: var(--text-secondary); }
    .empty-msg { color: var(--text-secondary); font-size: 13px; font-style: italic; }
  `],
})
export class ScenarioLabComponent {
  svc = inject(ScenarioService);
  private route = inject(ActivatedRoute);

  selectedType: VulnType = 'sql_injection';
  difficulty: 'beginner' | 'intermediate' | 'advanced' = 'beginner';

  loading      = signal(false);
  scenario     = signal<Scenario | null>(null);
  errorMessage = signal<string | null>(null);

  constructor() {
    this.route.queryParams.subscribe(p => {
      if (p['type']) this.selectedType = p['type'] as VulnType;
    });
  }

  generate(): void {
    this.loading.set(true);
    this.scenario.set(null);
    this.errorMessage.set(null);
    console.log('[ScenarioLab] Generating:', this.selectedType, this.difficulty);

    this.svc.generate(this.selectedType, this.difficulty)
      .pipe(finalize(() => this.loading.set(false)))
      .subscribe({
        next: result => {
          console.log('[ScenarioLab] Result:', result);
          this.scenario.set(result);
        },
        error: err => {
          console.error('[ScenarioLab] Error:', err);
          const detail = err?.error?.detail ?? err?.message ?? 'Generation failed';
          this.errorMessage.set(typeof detail === 'string' ? detail : JSON.stringify(detail));
        },
      });
  }

  /** Phase name → CSS color var */
  phaseColor(phase: string): string {
    return PHASE_COLORS[(phase || '').toLowerCase()] ?? 'var(--accent)';
  }

  /** Returns true for placeholder/empty payload strings */
  isPlaceholder(p: string): boolean {
    return PLACEHOLDER_PAYLOADS.has((p ?? '').toLowerCase().trim());
  }

  /** Payloads filtered to only real (non-placeholder) entries */
  realPayloads(): Array<{ payload: string; description: string; expected_outcome: string }> {
    return (this.scenario()?.payloads ?? []).filter(p => !this.isPlaceholder(p.payload));
  }

  /** True if code_examples has real (>50 char) non-placeholder code */
  hasRealCode(): boolean {
    const ex = this.scenario()?.code_examples;
    if (!ex) return false;
    const v = ex.vulnerable ?? '';
    const s = ex.secure ?? '';
    return (v.length > 50 && !this.isPlaceholder(v)) ||
           (s.length > 50 && !this.isPlaceholder(s));
  }

  /** Copy text to clipboard; briefly style the button as "copied" */
  copy(text: string, event: Event): void {
    navigator.clipboard.writeText(text).then(() => {
      const btn = (event.currentTarget as HTMLElement);
      btn.classList.add('copied');
      setTimeout(() => btn.classList.remove('copied'), 1500);
    });
  }
}
