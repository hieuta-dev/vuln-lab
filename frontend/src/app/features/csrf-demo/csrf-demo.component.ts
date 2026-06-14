// FILE: frontend/src/app/features/csrf-demo/csrf-demo.component.ts
// PURPOSE: CSRF demo — shows form with/without CSRF token based on security mode

import { Component, inject, signal, OnInit } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { HttpClient } from '@angular/common/http';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatButtonModule } from '@angular/material/button';
import { SecurityModeService } from '../../core/services/security-mode.service';
import { AsyncPipe } from '@angular/common';
import { environment } from '../../../environments/environment';

@Component({
  selector: 'app-csrf-demo',
  standalone: true,
  imports: [FormsModule, MatCardModule, MatFormFieldModule, MatInputModule, MatButtonModule, AsyncPipe],
  template: `
    <h2>CSRF Demo</h2>
    <p>Mode: <strong [style.color]="(svc.currentMode$ | async) === 'secure' ? '#4caf50' : '#f44336'">
      {{ svc.currentMode$ | async }}
    </strong></p>

    @if ((svc.currentMode$ | async) === 'vulnerable') {
      <p class="warning">⚠ Vulnerable: no CSRF token — form submits without validation</p>
    } @else {
      <p class="safe">✓ Secure: HMAC token required and validated server-side</p>
      <p>Token: <code>{{ csrfToken() || 'loading...' }}</code></p>
    }

    <mat-card class="action-card">
      <mat-card-content>
        <mat-form-field appearance="outline">
          <mat-label>Action to perform</mat-label>
          <input matInput [(ngModel)]="action" placeholder="e.g. change-password" />
        </mat-form-field>
        <button mat-raised-button color="primary" (click)="submit()">Submit Action</button>
      </mat-card-content>
    </mat-card>

    @if (result()) {
      <mat-card [class]="result()!.success ? 'result success' : 'result fail'">
        <mat-card-content>
          <strong>{{ result()!.success ? '✅ Action executed' : '❌ Action blocked' }}</strong>
          <p>{{ result()!.message }}</p>
        </mat-card-content>
      </mat-card>
    }
  `,
  styles: [`
    .action-card { max-width: 400px; margin: 16px 0; }
    mat-form-field { display: block; margin-bottom: 8px; }
    .warning { color: #f44336; font-size: 13px; }
    .safe { color: #4caf50; font-size: 13px; }
    .result { max-width: 400px; margin: 12px 0; }
    .success { border-left: 4px solid #4caf50; }
    .fail { border-left: 4px solid #f44336; }
  `],
})
export class CsrfDemoComponent implements OnInit {
  svc = inject(SecurityModeService);
  private http = inject(HttpClient);

  action = 'change-password';
  csrfToken = signal<string | null>(null);
  result = signal<{ success: boolean; message?: string } | null>(null);

  ngOnInit(): void { this.fetchToken(); }

  fetchToken(): void {
    this.http.get<{ csrf_token: string | null }>(`${environment.apiUrl}/csrf/token`).subscribe(
      r => this.csrfToken.set(r.csrf_token)
    );
  }

  submit(): void {
    const body: { action: string; csrf_token?: string | null } = { action: this.action };
    if (this.svc.currentMode() === 'secure') body.csrf_token = this.csrfToken();
    this.http.post<{ success: boolean; message?: string }>(`${environment.apiUrl}/csrf/action`, body).subscribe(
      r => this.result.set(r)
    );
  }
}
