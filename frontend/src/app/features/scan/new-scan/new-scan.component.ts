// FILE: frontend/src/app/features/scan/new-scan/new-scan.component.ts
// PURPOSE: New scan form — polished card layout with auth + headers sections

import { Component, inject, signal } from '@angular/core';
import { FormArray, FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatButtonModule } from '@angular/material/button';
import { MatExpansionModule } from '@angular/material/expansion';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatIconModule } from '@angular/material/icon';
import { ScanService } from '../../../core/services/scan.service';

@Component({
  selector: 'app-new-scan',
  standalone: true,
  imports: [ReactiveFormsModule, MatFormFieldModule, MatInputModule, MatButtonModule,
            MatExpansionModule, MatProgressSpinnerModule, MatIconModule],
  template: `
    <div class="fade-in">
      <div class="page-top">
        <h2>New Security Scan</h2>
        <p>VulnLab will probe your target across 13 OWASP vulnerability categories using AI-generated attack scenarios.</p>
      </div>

      <div class="form-card">
        <form [formGroup]="form" (ngSubmit)="submit()">

          <span class="section-label">Target</span>
          <mat-form-field appearance="outline" class="full-width">
            <mat-label>Target URL</mat-label>
            <mat-icon matPrefix>language</mat-icon>
            <input matInput formControlName="target_url" placeholder="https://example.com" />
            @if (form.get('target_url')?.invalid && form.get('target_url')?.touched) {
              <mat-error>Enter a valid URL (https://...)</mat-error>
            }
          </mat-form-field>

          <div class="two-col">
            <mat-form-field appearance="outline" class="full-width">
              <mat-label>Target Name</mat-label>
              <input matInput formControlName="target_name" placeholder="My Web App" />
              @if (form.get('target_name')?.invalid && form.get('target_name')?.touched) {
                <mat-error>Target name is required</mat-error>
              }
            </mat-form-field>
            <mat-form-field appearance="outline" class="full-width">
              <mat-label>Description (optional)</mat-label>
              <input matInput formControlName="description" />
            </mat-form-field>
          </div>

          <!-- Auth Info -->
          <mat-expansion-panel class="section-panel">
            <mat-expansion-panel-header>
              <mat-panel-title>
                <mat-icon class="panel-icon">lock_open</mat-icon>
                Authentication Info
              </mat-panel-title>
              <mat-panel-description>Optional — needed for broken auth testing</mat-panel-description>
            </mat-expansion-panel-header>
            <div class="panel-body" formGroupName="auth_info">
              <mat-form-field appearance="outline" class="full-width">
                <mat-label>Login URL</mat-label>
                <input matInput formControlName="login_url" placeholder="https://example.com/login" />
              </mat-form-field>
              <div class="two-col">
                <mat-form-field appearance="outline" class="full-width">
                  <mat-label>Username</mat-label>
                  <input matInput formControlName="username" />
                </mat-form-field>
                <mat-form-field appearance="outline" class="full-width">
                  <mat-label>Password</mat-label>
                  <input matInput type="password" formControlName="password" />
                </mat-form-field>
              </div>
              <mat-form-field appearance="outline" class="full-width">
                <mat-label>Bearer Token / Cookie (optional)</mat-label>
                <input matInput formControlName="token" />
              </mat-form-field>
            </div>
          </mat-expansion-panel>

          <!-- Custom Headers -->
          <mat-expansion-panel class="section-panel">
            <mat-expansion-panel-header>
              <mat-panel-title>
                <mat-icon class="panel-icon">tune</mat-icon>
                Custom Headers
              </mat-panel-title>
              <mat-panel-description>{{ headersArray.length }} header(s)</mat-panel-description>
            </mat-expansion-panel-header>
            <div class="panel-body" formArrayName="headers">
              @for (hdr of headersArray.controls; track $index) {
                <div [formGroupName]="$index" class="header-row">
                  <mat-form-field appearance="outline" class="hdr-key">
                    <mat-label>Name</mat-label>
                    <input matInput formControlName="key" placeholder="X-Custom-Header" />
                  </mat-form-field>
                  <mat-form-field appearance="outline" class="hdr-val">
                    <mat-label>Value</mat-label>
                    <input matInput formControlName="value" />
                  </mat-form-field>
                  <button mat-icon-button type="button" (click)="removeHeader($index)" class="remove-btn">
                    <mat-icon>close</mat-icon>
                  </button>
                </div>
              }
              <button mat-stroked-button type="button" (click)="addHeader()" class="add-header-btn">
                <mat-icon>add</mat-icon> Add Header
              </button>
            </div>
          </mat-expansion-panel>

          @if (error()) {
            <div class="error-banner"><mat-icon>error_outline</mat-icon> {{ error() }}</div>
          }

          <button class="submit-btn" type="submit" [disabled]="loading() || form.invalid">
            @if (loading()) {
              <mat-spinner diameter="20" class="btn-spinner"></mat-spinner> Starting Scan…
            } @else {
              <mat-icon>radar</mat-icon> Start Scan
            }
          </button>
        </form>
      </div>
    </div>
  `,
  styles: [`
    .page-top { margin-bottom: 24px; }
    h2 { font-size: 1.6rem; margin-bottom: 4px; }
    .form-card {
      max-width: 680px;
      background: var(--bg-surface); border: 1px solid var(--border);
      border-radius: var(--radius-lg); padding: 28px;
    }
    .full-width { width: 100%; display: block; }
    .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 4px; }
    .section-panel { margin: 12px 0; }
    .panel-icon { font-size: 18px; width: 18px; height: 18px; margin-right: 6px; color: var(--accent-light); }
    .panel-body { padding: 8px 0 0; display: flex; flex-direction: column; gap: 4px; }
    .header-row { display: flex; gap: 8px; align-items: center; }
    .hdr-key { flex: 1; }
    .hdr-val { flex: 2; }
    .remove-btn { color: var(--text-secondary); flex-shrink: 0; }
    .remove-btn:hover { color: var(--accent-danger); }
    .add-header-btn { margin-top: 4px; border-color: var(--border) !important; color: var(--text-secondary) !important; }
    .error-banner {
      display: flex; align-items: center; gap: 8px;
      background: rgba(239,68,68,.1); border: 1px solid rgba(239,68,68,.3);
      border-radius: var(--radius-md); padding: 10px 14px;
      color: var(--accent-danger); font-size: 13px; margin: 12px 0;
    }
    .submit-btn {
      width: 100%; height: 48px; margin-top: 16px;
      background: var(--accent); color: white; border: none;
      border-radius: var(--radius-md); font-size: 15px; font-weight: 700;
      cursor: pointer; display: flex; align-items: center; justify-content: center; gap: 8px;
      transition: all 0.2s ease; font-family: inherit;
    }
    .submit-btn:hover:not([disabled]) {
      background: #8b5cf6; transform: translateY(-1px);
      box-shadow: 0 8px 24px rgba(124,58,237,.4);
    }
    .submit-btn[disabled] { opacity: 0.6; cursor: not-allowed; }
    .btn-spinner { --mdc-circular-progress-active-indicator-color: white !important; }
  `],
})
export class NewScanComponent {
  private fb = inject(FormBuilder);
  private scanSvc = inject(ScanService);
  private router = inject(Router);

  loading = signal(false);
  error = signal('');

  form = this.fb.group({
    target_url:  ['', [Validators.required, Validators.pattern(/^https?:\/\/.+/)]],
    target_name: ['', Validators.required],
    description: [''],
    auth_info: this.fb.group({ login_url: [''], username: [''], password: [''], token: [''] }),
    headers: this.fb.array([]),
  });

  get headersArray(): FormArray { return this.form.get('headers') as FormArray; }
  addHeader(): void { this.headersArray.push(this.fb.group({ key: [''], value: [''] })); }
  removeHeader(i: number): void { this.headersArray.removeAt(i); }

  submit(): void {
    if (this.form.invalid) return;
    this.loading.set(true);
    const v = this.form.value;
    const auth = v.auth_info as Record<string, string>;
    this.scanSvc.startScan({
      target_url: v.target_url!,
      target_name: v.target_name!,
      description: v.description || undefined,
      auth_info: Object.values(auth).some(x => x) ? auth : null,
      headers: (v.headers as { key: string; value: string }[]).filter(h => h.key),
    }).subscribe({
      next: res => this.router.navigate(['/scan/session', res.session_id]),
      error: () => { this.loading.set(false); this.error.set('Failed to start scan'); },
    });
  }
}
