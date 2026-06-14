// FILE: frontend/src/app/features/scan/history/scan-history.component.ts
// PURPOSE: Scan history — table with severity chips, actions, PDF download

import { Component, OnInit, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { HttpClient } from '@angular/common/http';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatTooltipModule } from '@angular/material/tooltip';
import { DatePipe } from '@angular/common';
import { ScanService, ScanSession } from '../../../core/services/scan.service';
import { AuthService } from '../../../core/services/auth.service';
import { environment } from '../../../../environments/environment';

const SEV = ['critical','high','medium','low','info'];

@Component({
  selector: 'app-scan-history',
  standalone: true,
  imports: [RouterLink, MatButtonModule, MatIconModule, MatTooltipModule, DatePipe],
  template: `
    <div class="fade-in">
      <div class="history-header">
        <div>
          <h2>Scan History</h2>
          <p>{{ sessions().length }} scan(s) total</p>
        </div>
        <a mat-raised-button color="primary" routerLink="/scan/new">
          <mat-icon>add</mat-icon> New Scan
        </a>
      </div>

      @if (sessions().length === 0) {
        <div class="empty-state">
          <span class="empty-icon">🔍</span>
          <h3>No scans yet</h3>
          <p>Start your first scan to see results here.</p>
          <a mat-raised-button color="primary" routerLink="/scan/new">Start a Scan</a>
        </div>
      } @else {
        <div class="sessions-list">
          @for (s of sessions(); track s.id) {
            <div class="session-row" [routerLink]="['/scan/session', s.id]">
              <div class="col-info">
                <span class="target-name">{{ s.target_name }}</span>
                <a class="target-url" (click)="$event.stopPropagation()" [href]="s.target_url" target="_blank">
                  {{ s.target_url }}
                </a>
                <span class="scan-date">{{ s.started_at | date:'MMM d, y, h:mm a' }}</span>
              </div>

              <div class="col-status">
                <span [class]="'status-pill status-' + s.status">
                  @switch (s.status) {
                    @case ('running')   { <span class="dot dot-scanning"></span> Running }
                    @case ('completed') { <span class="dot dot-success"></span> Completed }
                    @case ('failed')    { <span class="dot dot-fail"></span> Failed }
                    @default            { <span class="dot"></span> Pending }
                  }
                </span>
              </div>

              <div class="col-vulns">
                @for (sev of sevOrder; track sev) {
                  @if (s.severity_counts[sev]) {
                    <span [class]="'pill pill-' + sev">{{ s.severity_counts[sev] }} {{ sev }}</span>
                  }
                }
                @if (!hasSevs(s)) { <span class="no-vulns">—</span> }
              </div>

              <div class="col-actions" (click)="$event.stopPropagation()">
                <button mat-icon-button [routerLink]="['/scan/session', s.id]" matTooltip="View Results">
                  <mat-icon>open_in_new</mat-icon>
                </button>
                <button mat-icon-button (click)="exportPdf(s.id)" matTooltip="Export PDF"
                        [disabled]="s.status !== 'completed'">
                  <mat-icon>picture_as_pdf</mat-icon>
                </button>
                <button mat-icon-button (click)="del(s.id)" matTooltip="Delete" class="btn-delete">
                  <mat-icon>delete_outline</mat-icon>
                </button>
              </div>
            </div>
          }
        </div>
      }
    </div>
  `,
  styles: [`
    .history-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 24px; }
    h2 { margin-bottom: 2px; }

    .empty-state {
      text-align: center; padding: 60px 20px;
      background: var(--bg-surface); border: 1px solid var(--border);
      border-radius: var(--radius-lg);
    }
    .empty-icon { font-size: 48px; display: block; margin-bottom: 12px; }
    .empty-state h3 { color: var(--text-primary); margin-bottom: 4px; }

    .sessions-list { display: flex; flex-direction: column; gap: 8px; }
    .session-row {
      display: grid; grid-template-columns: 1fr auto 1fr auto;
      gap: 16px; align-items: center;
      background: var(--bg-surface); border: 1px solid var(--border);
      border-radius: var(--radius-lg); padding: 14px 18px;
      cursor: pointer; transition: all 0.15s ease;
    }
    .session-row:hover { border-color: var(--accent); background: var(--bg-elevated); }

    .target-name { display: block; font-size: 14px; font-weight: 600; color: var(--text-primary); }
    .target-url  { display: block; font-size: 12px; color: var(--accent-light); margin: 2px 0; }
    .scan-date   { font-size: 11px; color: var(--text-secondary); }

    .status-pill {
      display: inline-flex; align-items: center; gap: 6px;
      padding: 4px 12px; border-radius: var(--radius-xl);
      font-size: 12px; font-weight: 600; white-space: nowrap;
    }
    .status-pending   { background: rgba(100,116,139,.15); color: var(--text-secondary); }
    .status-running   { background: rgba(124,58,237,.15);  color: var(--accent-light); }
    .status-completed { background: rgba(34,197,94,.15);   color: var(--accent-success); }
    .status-failed    { background: rgba(239,68,68,.15);   color: var(--accent-danger); }

    .dot { width: 7px; height: 7px; border-radius: 50%; display: inline-block; background: currentColor; }
    .dot-scanning { animation: pulse 1.5s infinite; }
    .dot-success  { background: var(--accent-success); }
    .dot-fail     { background: var(--accent-danger); }

    .col-vulns { display: flex; flex-wrap: wrap; gap: 4px; }
    .no-vulns { font-size: 12px; color: var(--text-secondary); }

    .col-actions { display: flex; gap: 2px; }
    .btn-delete { color: var(--text-secondary); }
    .btn-delete:hover { color: var(--accent-danger); }
  `],
})
export class ScanHistoryComponent implements OnInit {
  private scanSvc = inject(ScanService);
  private auth = inject(AuthService);
  private http = inject(HttpClient);

  sessions = signal<ScanSession[]>([]);
  sevOrder = SEV;

  ngOnInit(): void { this.load(); }
  load(): void { this.scanSvc.getSessions().subscribe(s => this.sessions.set(s)); }
  hasSevs(s: ScanSession): boolean { return Object.values(s.severity_counts).some(v => v > 0); }

  exportPdf(id: number): void {
    const token = this.auth.getToken();
    this.http.get(`${environment.apiUrl}/scans/sessions/${id}/export-pdf`,
      { responseType: 'blob', headers: token ? { Authorization: `Bearer ${token}` } : {} }
    ).subscribe(blob => {
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `vulnlab-scan-${id}.pdf`;
      a.click();
    });
  }

  del(id: number): void {
    if (!confirm('Delete this scan?')) return;
    this.scanSvc.deleteSession(id).subscribe(() => this.load());
  }
}
