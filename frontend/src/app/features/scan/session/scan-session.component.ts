// FILE: frontend/src/app/features/scan/session/scan-session.component.ts
// PURPOSE: Live scan view — sorted results, reproduce steps, collapsible passed group, PDF export

import { Component, OnDestroy, OnInit, computed, inject, signal } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { FormsModule } from '@angular/forms';
import { HttpClient } from '@angular/common/http';
import { MatCardModule } from '@angular/material/card';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatExpansionModule } from '@angular/material/expansion';
import { DatePipe, UpperCasePipe } from '@angular/common';
import { ScanService, ScanResult, LiveResults, SessionDetail } from '../../../core/services/scan.service';
import { AuthService } from '../../../core/services/auth.service';
import { environment } from '../../../../environments/environment';

const VULN_ICONS: Record<string, string> = {
  sql_injection: '💉', xss: '🖥️', csrf: '🔄', file_upload: '📂',
  broken_auth: '🔑', security_misconfig: '⚙️', sensitive_data_exposure: '👁️',
  logging_monitoring: '📋', supply_chain: '📦', cryptographic_failure: '🔐',
  insecure_design: '🏗️', exceptional_conditions: '⚡', underprotected_apis: '🌐',
};

const VULN_LABELS: Record<string, string> = {
  sql_injection: 'SQL Injection', xss: 'Cross-Site Scripting', csrf: 'CSRF',
  file_upload: 'Malicious File Upload', broken_auth: 'Broken Authentication',
  security_misconfig: 'Security Misconfiguration', sensitive_data_exposure: 'Sensitive Data Exposure',
  logging_monitoring: 'Logging & Monitoring', supply_chain: 'Supply Chain',
  cryptographic_failure: 'Cryptographic Failure', insecure_design: 'Insecure Design',
  exceptional_conditions: 'Exceptional Conditions', underprotected_apis: 'Underprotected APIs',
};

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

// A real vulnerability was found — status="success" with a meaningful severity
function isVuln(r: ScanResult): boolean {
  return r.status === 'success' && r.severity !== null && r.severity !== 'info';
}
// No vulnerability detected — backend set status="passed", severity=null
function isPassed(r: ScanResult): boolean {
  return r.status === 'passed';
}

@Component({
  selector: 'app-scan-session',
  standalone: true,
  imports: [FormsModule, MatCardModule, MatProgressBarModule, MatProgressSpinnerModule,
            MatButtonModule, MatIconModule, MatFormFieldModule, MatInputModule,
            MatExpansionModule, DatePipe, UpperCasePipe],
  template: `
    <!-- ── Header ─────────────────────────────────────────────────────── -->
    @if (data()) {
      <div class="session-header">
        <div>
          <h2>{{ data()!.target.target_name }}</h2>
          <a class="target-url" [href]="data()!.target.target_url" target="_blank">
            {{ data()!.target.target_url }}
          </a>
        </div>
        <div class="header-right">
          <span [class]="'status-pill status-' + data()!.session.status">
            {{ data()!.session.status | uppercase }}
          </span>
          <small>{{ data()!.session.started_at | date:'medium' }}</small>
          @if (data()!.session.status === 'completed') {
            <button mat-raised-button color="accent" class="pdf-btn" (click)="exportPdf()">
              <mat-icon>picture_as_pdf</mat-icon> Export PDF
            </button>
          }
        </div>
      </div>
    }

    <!-- ── Progress ────────────────────────────────────────────────────── -->
    @if (live() && data() && data()!.session.status !== 'completed') {
      <div class="progress-row">
        <mat-progress-bar mode="determinate" [value]="progressPct()"></mat-progress-bar>
        <span class="progress-label">{{ live()!.completed }} / {{ live()!.total }}</span>
      </div>
    }

    <!-- ── Summary bar ──────────────────────────────────────────────────── -->
    @if (live() && live()!.completed > 0) {
      <div class="summary-bar">
        <div class="summary-stat">
          <span class="stat-num">{{ live()!.total }}</span>
          <span class="stat-lbl">Total Checks</span>
        </div>
        <div class="summary-stat vuln-stat" [class.has-vulns]="vulnCount() > 0">
          <span class="stat-num">{{ vulnCount() }}</span>
          <span class="stat-lbl">Vulnerabilities</span>
        </div>
        <div class="summary-stat passed-stat">
          <span class="stat-num">{{ passedCount() }}</span>
          <span class="stat-lbl">Passed</span>
        </div>
        <div class="summary-stat info-stat">
          <span class="stat-num">{{ needsInfoCount() }}</span>
          <span class="stat-lbl">Needs Info</span>
        </div>
      </div>
    }

    <!-- ── Vulnerability cards (sorted by severity) ─────────────────────── -->
    @if (sortedVulns().length > 0) {
      <h3 class="group-title">
        <mat-icon class="gtitle-icon">warning</mat-icon>
        Vulnerabilities Found ({{ sortedVulns().length }})
      </h3>
      @for (r of sortedVulns(); track r.vuln_type) {
        <div class="finding-card finding-card--vuln">
          <div class="card-top">
            <span class="vuln-icon">{{ icon(r.vuln_type) }}</span>
            <span class="vuln-name">{{ label(r.vuln_type) }}</span>
            <span [class]="'sev-pill sev-' + r.severity">{{ r.severity }}</span>
          </div>

          <!-- Finding summary -->
          <p class="finding-summary">{{ r.findings?.summary }}</p>

          <!-- How to Reproduce (expandable) -->
          @if (r.reproduce_steps?.length) {
            <mat-expansion-panel class="repro-panel">
              <mat-expansion-panel-header>
                <mat-panel-title class="repro-title">
                  <mat-icon>bug_report</mat-icon> How to Reproduce
                </mat-panel-title>
              </mat-expansion-panel-header>
              <ol class="repro-steps">
                @for (step of r.reproduce_steps!; track $index) {
                  <li [class.repro-step-cmd]="step.startsWith('curl') || step.startsWith('for ')">
                    {{ step }}
                  </li>
                }
              </ol>
            </mat-expansion-panel>
          }
        </div>
      }
    }

    <!-- ── Needs Info cards ──────────────────────────────────────────────── -->
    @if (needsInfoResults().length > 0) {
      <h3 class="group-title">
        <mat-icon class="gtitle-icon warn-icon">help_outline</mat-icon>
        Needs More Information ({{ needsInfoResults().length }})
      </h3>
      @for (r of needsInfoResults(); track r.vuln_type) {
        <div class="finding-card finding-card--info">
          <div class="card-top">
            <span class="vuln-icon">{{ icon(r.vuln_type) }}</span>
            <span class="vuln-name">{{ label(r.vuln_type) }}</span>
            <span class="sev-pill sev-needs-info">NEEDS INFO</span>
          </div>
          <p class="finding-summary warn-text">{{ r.missing_info }}</p>
          <div class="provide-info">
            <mat-form-field appearance="outline" class="full-width">
              <mat-label>Provide missing information</mat-label>
              <input matInput [(ngModel)]="infoInputs[r.vuln_type]"
                     placeholder="e.g. login URL + admin:password123" />
            </mat-form-field>
            <button mat-raised-button color="primary" (click)="retry(r)">
              <mat-icon>refresh</mat-icon> Retry
            </button>
          </div>
        </div>
      }
    }

    <!-- ── Scanning cards ───────────────────────────────────────────────── -->
    @if (scanningResults().length > 0) {
      <h3 class="group-title">
        <mat-icon class="gtitle-icon scan-icon">radar</mat-icon>
        Scanning… ({{ scanningResults().length }} remaining)
      </h3>
      <div class="scanning-grid">
        @for (r of scanningResults(); track r.vuln_type) {
          <div class="scanning-chip">
            <mat-spinner diameter="14"></mat-spinner>
            <span>{{ label(r.vuln_type) }}</span>
          </div>
        }
      </div>
    }

    <!-- ── Passed checks (collapsed group) ──────────────────────────────── -->
    @if (passedResults().length > 0 && live()!.completed === live()!.total) {
      <div class="passed-group">
        <button class="passed-toggle" (click)="showPassed.set(!showPassed())">
          <mat-icon>{{ showPassed() ? 'expand_less' : 'expand_more' }}</mat-icon>
          {{ showPassed() ? 'Hide' : 'Show' }} {{ passedResults().length }} passed checks
        </button>
        @if (showPassed()) {
          <div class="passed-list">
            @for (r of passedResults(); track r.vuln_type) {
              <div class="passed-row">
                <mat-icon class="pass-icon">check_circle</mat-icon>
                <span class="pass-name">{{ label(r.vuln_type) }}</span>
                <span class="pass-msg">{{ r.findings?.summary }}</span>
              </div>
            }
          </div>
        }
      </div>
    }
  `,
  styles: [`
    /* ── Header ─────────────────────────────────────────────────────────── */
    .session-header { display: flex; justify-content: space-between; align-items: flex-start;
                      margin-bottom: 20px; }
    h2 { margin: 0 0 4px; font-size: 1.4rem; }
    .target-url { font-size: 13px; color: var(--accent-light); }
    .header-right { display: flex; flex-direction: column; align-items: flex-end; gap: 6px; }
    .status-pill { padding: 4px 12px; border-radius: var(--radius-xl); font-size: 11px; font-weight: 700; }
    .status-pending   { background: rgba(100,116,139,.2); color: var(--text-secondary); }
    .status-running   { background: rgba(124,58,237,.2);  color: var(--accent-light); }
    .status-completed { background: rgba(34,197,94,.2);   color: var(--accent-success); }
    .status-failed    { background: rgba(239,68,68,.2);   color: var(--accent-danger); }
    .pdf-btn { --mdc-filled-button-container-color: #22c55e !important; color: #000 !important; }
    small { font-size: 11px; color: var(--text-secondary); }

    /* ── Progress ────────────────────────────────────────────────────────── */
    .progress-row { display: flex; align-items: center; gap: 12px; margin-bottom: 16px; }
    .progress-label { font-size: 12px; color: var(--text-secondary); white-space: nowrap; }

    /* ── Summary bar ─────────────────────────────────────────────────────── */
    .summary-bar {
      display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 24px;
      padding: 16px 20px; background: var(--bg-surface);
      border: 1px solid var(--border); border-radius: var(--radius-lg);
    }
    .summary-stat { display: flex; flex-direction: column; align-items: center;
                    min-width: 80px; }
    .stat-num { font-size: 26px; font-weight: 800; color: var(--text-secondary); }
    .stat-lbl { font-size: 11px; color: var(--text-secondary); }
    .vuln-stat.has-vulns .stat-num { color: var(--accent-danger); }
    .passed-stat .stat-num { color: var(--accent-success); }
    .info-stat .stat-num { color: var(--accent-warning); }

    /* ── Group titles ────────────────────────────────────────────────────── */
    .group-title {
      display: flex; align-items: center; gap: 8px;
      font-size: 14px; font-weight: 700; margin: 20px 0 10px;
      color: var(--text-primary);
    }
    .gtitle-icon { font-size: 18px; width: 18px; height: 18px; color: var(--accent-danger); }
    .warn-icon   { color: var(--accent-warning); }
    .scan-icon   { color: var(--accent-light); }

    /* ── Finding cards ───────────────────────────────────────────────────── */
    .finding-card {
      background: var(--bg-surface); border: 1px solid var(--border);
      border-radius: var(--radius-lg); padding: 16px; margin-bottom: 10px;
    }
    .finding-card--vuln { border-left: 3px solid var(--accent-danger); }
    .finding-card--info { border-left: 3px solid var(--accent-warning); }

    .card-top { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }
    .vuln-icon { font-size: 20px; flex-shrink: 0; }
    .vuln-name { font-size: 14px; font-weight: 700; color: var(--text-primary); flex: 1; }

    .sev-pill {
      padding: 3px 10px; border-radius: var(--radius-xl);
      font-size: 10px; font-weight: 700; white-space: nowrap;
    }
    .sev-critical      { background: rgba(239,68,68,.15);   color: #ef4444; }
    .sev-high          { background: rgba(249,115,22,.15);  color: #f97316; }
    .sev-medium        { background: rgba(234,179,8,.15);   color: #eab308; }
    .sev-low           { background: rgba(34,197,94,.15);   color: #22c55e; }
    .sev-info          { background: rgba(100,116,139,.15); color: var(--text-secondary); }
    .sev-needs-info    { background: rgba(245,158,11,.15);  color: var(--accent-warning); }

    .finding-summary { font-size: 13px; color: var(--text-secondary); margin: 0 0 8px; }
    .warn-text { color: var(--accent-warning); }

    /* ── Reproduce panel ─────────────────────────────────────────────────── */
    .repro-panel { background: transparent !important; border: none !important;
                   box-shadow: none !important; margin: 4px 0 0 !important; }
    .repro-title { display: flex; align-items: center; gap: 6px; font-size: 13px;
                   font-weight: 600; color: var(--accent-light); }
    .repro-title mat-icon { font-size: 16px; width: 16px; height: 16px; }
    .repro-steps {
      margin: 8px 0 0; padding: 12px 16px;
      background: #0d0d14; border-radius: var(--radius-md);
      border-left: 2px solid var(--accent);
      list-style: none; counter-reset: steps;
    }
    .repro-steps li {
      font-size: 12px; color: #e2e8f0;
      font-family: 'JetBrains Mono', 'Courier New', monospace;
      padding: 3px 0; line-height: 1.5;
    }
    .repro-step-cmd {
      background: rgba(124,58,237,.08); border-radius: 4px;
      padding: 4px 6px !important; margin: 2px 0;
      color: var(--accent-light) !important;
    }

    /* ── Needs info form ─────────────────────────────────────────────────── */
    .provide-info { display: flex; align-items: center; gap: 12px; margin-top: 8px; }
    .full-width { flex: 1; }

    /* ── Scanning chips ──────────────────────────────────────────────────── */
    .scanning-grid { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 16px; }
    .scanning-chip {
      display: inline-flex; align-items: center; gap: 8px;
      background: var(--bg-surface); border: 1px solid var(--border);
      border-radius: var(--radius-xl); padding: 5px 12px;
      font-size: 12px; color: var(--text-secondary);
    }

    /* ── Passed group ────────────────────────────────────────────────────── */
    .passed-group { margin-top: 20px; }
    .passed-toggle {
      display: flex; align-items: center; gap: 6px;
      background: none; border: 1px solid var(--border);
      border-radius: var(--radius-md); padding: 8px 14px;
      color: var(--text-secondary); font-size: 13px; cursor: pointer;
      font-family: inherit; transition: all 0.15s;
    }
    .passed-toggle:hover { border-color: var(--accent-success); color: var(--accent-success); }
    .passed-list {
      margin-top: 8px; background: var(--bg-surface);
      border: 1px solid var(--border); border-radius: var(--radius-md);
      overflow: hidden;
    }
    .passed-row {
      display: flex; align-items: center; gap: 10px;
      padding: 10px 14px; border-bottom: 1px solid var(--border);
      font-size: 13px;
    }
    .passed-row:last-child { border-bottom: none; }
    .pass-icon { color: var(--accent-success); font-size: 18px; flex-shrink: 0; }
    .pass-name { font-weight: 600; color: var(--text-primary); min-width: 200px; }
    .pass-msg  { color: var(--text-secondary); font-size: 12px; }
  `],
})
export class ScanSessionComponent implements OnInit, OnDestroy {
  private route    = inject(ActivatedRoute);
  private scanSvc  = inject(ScanService);
  private auth     = inject(AuthService);
  private http     = inject(HttpClient);

  data        = signal<SessionDetail | null>(null);
  live        = signal<LiveResults | null>(null);
  infoInputs: Record<string, string> = {};
  showPassed  = signal(false);

  private sessionId    = 0;
  private pollInterval: ReturnType<typeof setInterval> | null = null;

  // ── Computed result groups ─────────────────────────────────────────────
  private allResults = computed(() => this.live()?.results ?? []);

  sortedVulns = computed(() =>
    this.allResults()
      .filter(isVuln)
      .sort((a, b) => SEV_ORDER.indexOf(a.severity ?? 'info') - SEV_ORDER.indexOf(b.severity ?? 'info'))
  );

  needsInfoResults  = computed(() => this.allResults().filter(r => r.status === 'needs_info' || r.status === 'failed'));
  scanningResults   = computed(() => this.allResults().filter(r => r.status === 'scanning'));
  passedResults     = computed(() => this.allResults().filter(isPassed));

  vulnCount      = computed(() => this.sortedVulns().length);
  passedCount    = computed(() => this.passedResults().length);
  needsInfoCount = computed(() => this.needsInfoResults().length);

  ngOnInit(): void {
    this.sessionId = +this.route.snapshot.params['id'];
    this.scanSvc.getSession(this.sessionId).subscribe(d => this.data.set(d));
    this.poll();
    this.pollInterval = setInterval(() => this.poll(), 3000);
  }

  ngOnDestroy(): void {
    if (this.pollInterval) clearInterval(this.pollInterval);
  }

  poll(): void {
    this.scanSvc.getResults(this.sessionId).subscribe(r => {
      this.live.set(r);
      if (r.session_status === 'completed' || r.session_status === 'failed') {
        if (this.pollInterval) { clearInterval(this.pollInterval); this.pollInterval = null; }
        this.scanSvc.getSession(this.sessionId).subscribe(d => this.data.set(d));
      }
    });
  }

  progressPct(): number {
    const l = this.live();
    return (l && l.total) ? Math.round((l.completed / l.total) * 100) : 0;
  }

  icon(vt: string): string  { return VULN_ICONS[vt]  ?? '🔍'; }
  label(vt: string): string { return VULN_LABELS[vt] ?? vt; }

  retry(r: ScanResult): void {
    this.scanSvc.provideInfo(this.sessionId, r.vuln_type, this.infoInputs[r.vuln_type] || '').subscribe(() => this.poll());
  }

  exportPdf(): void {
    const token = this.auth.getToken();
    const url   = `${environment.apiUrl}/scans/sessions/${this.sessionId}/export-pdf`;
    this.http.get(url, {
      responseType: 'blob',
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    }).subscribe(blob => {
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `vulnlab-scan-${this.sessionId}.pdf`;
      a.click();
    });
  }
}
