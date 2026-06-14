// FILE: frontend/src/app/features/dashboard/dashboard.component.ts
// PURPOSE: Main dashboard — scan stats, vulnerability grid, quick demo links

import { Component, OnInit, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { MatCardModule } from '@angular/material/card';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { ScenarioService } from '../../core/services/scenario.service';
import { ScanService, ScanSession } from '../../core/services/scan.service';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [RouterLink, MatCardModule, MatButtonModule, MatIconModule],
  template: `
    <div class="fade-in">
      <div class="page-hero">
        <h1>Security Training Platform</h1>
        <p class="hero-sub">Explore OWASP Top 10 vulnerabilities. Toggle between Vulnerable and Secure mode in the toolbar to see real-time behavioral differences.</p>
      </div>

      <!-- Stats row -->
      <div class="stats-row">
        <div class="stat-card">
          <span class="stat-icon">🔍</span>
          <div>
            <div class="stat-num">{{ completedScans() }}</div>
            <div class="stat-label">Scans Completed</div>
          </div>
        </div>
        <div class="stat-card">
          <span class="stat-icon">⚠️</span>
          <div>
            <div class="stat-num">{{ totalVulns() }}</div>
            <div class="stat-label">Vulnerabilities Found</div>
          </div>
        </div>
        <div class="stat-card">
          <span class="stat-icon">🎯</span>
          <div>
            <div class="stat-num">{{ uniqueTargets() }}</div>
            <div class="stat-label">Targets Scanned</div>
          </div>
        </div>
        <a class="cta-card" routerLink="/scan/new">
          <mat-icon>radar</mat-icon>
          <span>Start New Scan</span>
          <mat-icon class="arrow">arrow_forward</mat-icon>
        </a>
      </div>

      <!-- Vuln grid -->
      <h2 class="section-title">Vulnerability Scenarios</h2>
      <p class="section-desc">Select any vulnerability to generate an AI-powered lab scenario.</p>
      <div class="vuln-grid">
        @for (v of svc.VULN_TYPES; track v.id) {
          <a class="vuln-card" [routerLink]="['/scenario-lab']" [queryParams]="{type: v.id}">
            <span class="vuln-name">{{ v.label }}</span>
            <span class="vuln-cta">Generate Scenario →</span>
          </a>
        }
      </div>

      <!-- Demo links -->
      <h2 class="section-title" style="margin-top:32px">Live Interactive Demos</h2>
      <div class="demo-row">
        <a class="demo-btn" routerLink="/auth-demo">
          <span>💉</span> SQL Injection
        </a>
        <a class="demo-btn" routerLink="/xss-demo">
          <span>🖥️</span> XSS Comments
        </a>
        <a class="demo-btn" routerLink="/upload-demo">
          <span>📂</span> File Upload
        </a>
        <a class="demo-btn" routerLink="/csrf-demo">
          <span>🔄</span> CSRF Demo
        </a>
      </div>
    </div>
  `,
  styles: [`
    .page-hero { margin-bottom: 28px; }
    h1 { font-size: 2rem; font-weight: 800; margin-bottom: 8px; color: var(--text-primary); }
    .hero-sub { font-size: 14px; color: var(--text-secondary); max-width: 600px; }

    .stats-row { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 32px; }

    .stat-card {
      display: flex; align-items: center; gap: 14px;
      background: var(--bg-surface); border: 1px solid var(--border);
      border-radius: var(--radius-lg); padding: 16px 20px; flex: 1; min-width: 140px;
      transition: border-color 0.2s;
    }
    .stat-card:hover { border-color: var(--accent); }
    .stat-icon { font-size: 28px; line-height: 1; }
    .stat-num { font-size: 28px; font-weight: 800; color: var(--accent-light); line-height: 1; }
    .stat-label { font-size: 12px; color: var(--text-secondary); margin-top: 2px; }

    .cta-card {
      display: flex; align-items: center; gap: 10px;
      background: linear-gradient(135deg, var(--accent), #5b21b6);
      border: 1px solid rgba(124,58,237,.4); border-radius: var(--radius-lg);
      padding: 16px 24px; color: white; text-decoration: none;
      font-weight: 700; font-size: 15px; cursor: pointer;
      transition: all 0.2s ease; white-space: nowrap;
    }
    .cta-card:hover { transform: translateY(-2px); box-shadow: 0 8px 24px rgba(124,58,237,.4); color: white; }
    .cta-card mat-icon { font-size: 22px; width: 22px; height: 22px; }
    .arrow { margin-left: auto; }

    .section-title { font-size: 1.15rem; font-weight: 700; margin-bottom: 4px; color: var(--text-primary); }
    .section-desc  { font-size: 13px; color: var(--text-secondary); margin-bottom: 16px; }

    .vuln-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 10px; }

    .vuln-card {
      display: flex; flex-direction: column; gap: 6px;
      background: var(--bg-surface); border: 1px solid var(--border);
      border-radius: var(--radius-md); padding: 16px;
      text-decoration: none; cursor: pointer;
      transition: all 0.2s ease;
    }
    .vuln-card:hover {
      border-color: var(--accent);
      transform: translateY(-2px);
      box-shadow: 0 8px 24px rgba(124,58,237,.15);
    }
    .vuln-name { font-size: 13px; font-weight: 600; color: var(--text-primary); }
    .vuln-cta  { font-size: 11px; color: var(--accent-light); }

    .demo-row { display: flex; gap: 10px; flex-wrap: wrap; }
    .demo-btn {
      display: inline-flex; align-items: center; gap: 8px;
      background: rgba(239,68,68,.1); border: 1px solid rgba(239,68,68,.3);
      border-radius: var(--radius-md); padding: 10px 18px;
      color: #fca5a5; font-weight: 600; font-size: 13px;
      text-decoration: none; transition: all 0.2s ease;
    }
    .demo-btn:hover {
      background: rgba(239,68,68,.2); border-color: var(--accent-danger);
      color: white; transform: translateY(-1px);
    }
  `],
})
export class DashboardComponent implements OnInit {
  svc = inject(ScenarioService);
  private scanSvc = inject(ScanService);
  sessions = signal<ScanSession[]>([]);

  ngOnInit(): void { this.scanSvc.getSessions().subscribe(s => this.sessions.set(s)); }

  completedScans(): number { return this.sessions().filter(s => s.status === 'completed').length; }
  uniqueTargets(): number  { return new Set(this.sessions().map(s => s.target_url)).size; }
  totalVulns(): number {
    return this.sessions().reduce((a, s) => a + Object.values(s.severity_counts).reduce((x, y) => x + y, 0), 0);
  }
}
