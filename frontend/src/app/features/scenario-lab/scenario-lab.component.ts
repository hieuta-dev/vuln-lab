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
import { ScenarioService, Scenario, VulnType } from '../../core/services/scenario.service';
import { SourceViewerComponent } from '../../shared/components/source-viewer/source-viewer.component';
import { PayloadBadgeComponent } from '../../shared/components/payload-badge/payload-badge.component';

@Component({
  selector: 'app-scenario-lab',
  standalone: true,
  imports: [
    FormsModule, MatFormFieldModule, MatSelectModule, MatButtonModule,
    MatCardModule, MatProgressSpinnerModule, MatChipsModule, MatExpansionModule,
    MatIconModule, SourceViewerComponent, PayloadBadgeComponent,
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
          <div class="scenario-header">
            <h3>{{ scenario()!.title }}</h3>
            <div class="scenario-meta">
              <span [class]="'sev-badge sev-' + scenario()!.risk?.severity?.toLowerCase()">
                CVSS {{ scenario()!.risk?.cvss_score }} — {{ scenario()!.risk?.severity }}
              </span>
              <span class="owasp-tag">{{ scenario()!.risk?.owasp_category }}</span>
            </div>
          </div>

          <p class="scenario-desc">{{ scenario()!.description }}</p>

          <mat-expansion-panel [expanded]="true">
            <mat-expansion-panel-header>
              <mat-panel-title>⚔ Attack Steps</mat-panel-title>
            </mat-expansion-panel-header>
            @if (scenario()!.steps?.length) {
              @for (s of scenario()!.steps; track s.step) {
                <div class="step">
                  <div class="step-header">
                    <span class="step-num">{{ s.step }}</span>
                    <span class="step-phase">{{ s.phase }}</span>
                    <strong>{{ s.title }}</strong>
                  </div>
                  <p>{{ s.description }}</p>
                  @if (s.payload) { <app-payload-badge [payload]="s.payload" /> }
                </div>
              }
            } @else {
              <p>No steps available.</p>
            }
          </mat-expansion-panel>

          <mat-expansion-panel>
            <mat-expansion-panel-header>
              <mat-panel-title>💣 Payloads</mat-panel-title>
            </mat-expansion-panel-header>
            @if (scenario()!.payloads?.length) {
              @for (p of scenario()!.payloads; track p.payload) {
                <div class="payload-item">
                  <app-payload-badge [payload]="p.payload" />
                  <p class="payload-desc"><em>{{ p.description }}</em></p>
                  <p class="payload-expected">Expected: {{ p.expected_outcome }}</p>
                </div>
              }
            } @else {
              <p>No payloads available.</p>
            }
          </mat-expansion-panel>

          <mat-expansion-panel>
            <mat-expansion-panel-header>
              <mat-panel-title>🛡 Defense Tips</mat-panel-title>
            </mat-expansion-panel-header>
            @if (scenario()!.defense_tips?.length) {
              <ul class="tips-list">
                @for (t of scenario()!.defense_tips; track t) { <li>{{ t }}</li> }
              </ul>
            } @else {
              <p>No defense tips available.</p>
            }
          </mat-expansion-panel>

          @if (scenario()!.code_examples?.vulnerable || scenario()!.code_examples?.secure) {
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

    .sev-badge {
      padding: 3px 10px; border-radius: var(--radius-xl);
      font-size: 11px; font-weight: 700;
    }
    .sev-critical { background: rgba(239,68,68,.15); color: #ef4444; }
    .sev-high     { background: rgba(249,115,22,.15); color: #f97316; }
    .sev-medium   { background: rgba(234,179,8,.15);  color: #eab308; }
    .sev-low      { background: rgba(34,197,94,.15);  color: #22c55e; }

    .owasp-tag { font-size: 12px; color: var(--text-secondary); }
    .scenario-desc { color: var(--text-secondary); margin-bottom: 12px; }

    mat-expansion-panel { margin-bottom: 8px; }

    .step { margin: 12px 0; padding: 10px 12px; border-left: 3px solid var(--accent); background: var(--bg-elevated); border-radius: 0 var(--radius-sm) var(--radius-sm) 0; }
    .step-header { display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }
    .step-num { background: var(--accent); color: white; width: 22px; height: 22px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 11px; font-weight: 700; flex-shrink: 0; }
    .step-phase { font-size: 10px; font-weight: 700; color: var(--accent-light); text-transform: uppercase; }
    .step p { margin: 4px 0 0; font-size: 13px; color: var(--text-secondary); }

    .payload-item { margin: 12px 0; padding: 8px 0; border-bottom: 1px solid var(--border); }
    .payload-desc { font-size: 13px; color: var(--text-secondary); margin: 4px 0 2px; }
    .payload-expected { font-size: 12px; color: var(--text-secondary); margin: 0; }

    .tips-list { margin: 0; padding-left: 20px; }
    .tips-list li { font-size: 13px; margin-bottom: 6px; color: var(--text-secondary); }
  `],
})
export class ScenarioLabComponent {
  svc = inject(ScenarioService);
  private route = inject(ActivatedRoute);

  // Plain properties (NOT signals) so [(ngModel)] two-way binding works correctly
  selectedType: VulnType = 'sql_injection';
  difficulty: 'beginner' | 'intermediate' | 'advanced' = 'beginner';

  loading = signal(false);
  scenario = signal<Scenario | null>(null);
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
          this.errorMessage.set(
            typeof detail === 'string' ? detail : JSON.stringify(detail)
          );
        },
      });
  }

  severityColor(sev: string): string {
    return ({
      Critical: '#b00020', High: '#e65100', Medium: '#f57f17', Low: '#388e3c',
    } as Record<string, string>)[sev] ?? '#666';
  }
}
