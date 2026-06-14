// FILE: frontend/src/app/features/auth-demo/auth-demo.component.ts
// PURPOSE: Login form demo for SQL Injection vulnerability
// VULNERABLE MODE: raw SQL concat → ' OR '1'='1 bypass works
// SECURE MODE: parameterised query + bcrypt — same payload is blocked

import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { AuthService, LoginResponse } from '../../core/services/auth.service';
import { SecurityModeService } from '../../core/services/security-mode.service';
import { SourceViewerComponent } from '../../shared/components/source-viewer/source-viewer.component';
import { PayloadBadgeComponent } from '../../shared/components/payload-badge/payload-badge.component';
import { AsyncPipe } from '@angular/common';

const VULN_CODE = `# VULNERABLE: raw string concat
sql = f"SELECT * FROM users WHERE username='{username}' AND password_plain='{password}'"
result = db.execute(text(sql))  # ' OR '1'='1 bypasses this entirely`;

const SECURE_CODE = `# SECURE: parameterised query + bcrypt
result = db.execute(
    text("SELECT * FROM users WHERE username=:u"),
    {"u": username}
)
row = result.fetchone()
bcrypt.checkpw(password.encode(), row.password_hash.encode())`;

@Component({
  selector: 'app-auth-demo',
  standalone: true,
  imports: [
    FormsModule, MatFormFieldModule, MatInputModule, MatButtonModule,
    MatCardModule, MatProgressSpinnerModule, SourceViewerComponent,
    PayloadBadgeComponent, AsyncPipe,
  ],
  template: `
    <h2>SQL Injection — Login Demo</h2>
    <p>Mode: <strong [style.color]="(svc.currentMode$ | async) === 'secure' ? '#4caf50' : '#f44336'">
      {{ svc.currentMode$ | async }}
    </strong></p>

    <div class="try-payloads">
      <p>Try these payloads in the username field:</p>
      @for (p of sqliPayloads; track p) {
        <app-payload-badge [payload]="p" />
      }
    </div>

    <mat-card class="login-card">
      <mat-card-content>
        <mat-form-field appearance="outline">
          <mat-label>Username</mat-label>
          <input matInput [(ngModel)]="username" placeholder="' OR '1'='1" />
        </mat-form-field>
        <mat-form-field appearance="outline">
          <mat-label>Password</mat-label>
          <input matInput type="password" [(ngModel)]="password" placeholder="anything" />
        </mat-form-field>
        <button mat-raised-button color="primary" (click)="login()" [disabled]="loading()">
          @if (loading()) { <mat-spinner diameter="20"></mat-spinner> } @else { Login }
        </button>
      </mat-card-content>
    </mat-card>

    @if (result()) {
      <mat-card [class]="result()!.success ? 'result-card success' : 'result-card fail'">
        <mat-card-content>
          <strong>{{ result()!.success ? '✅ Login Successful' : '❌ Login Failed' }}</strong>
          @if (result()!.user) {
            <p>User: {{ result()!.user!.username }} (role: {{ result()!.user!.role }})</p>
          }
          <p>{{ result()!.message }}</p>
          <p>Mode: {{ result()!.mode }}</p>
        </mat-card-content>
      </mat-card>
    }

    <h3>Source Code</h3>
    <app-source-viewer [vulnerable]="vulnCode" [secure]="secureCode" />
  `,
  styles: [`
    .login-card { max-width: 400px; margin: 16px 0; }
    mat-form-field { display: block; margin-bottom: 8px; }
    .result-card { max-width: 400px; margin: 16px 0; }
    .success { border-left: 4px solid #f44336; }
    .fail { border-left: 4px solid #4caf50; }
    .try-payloads { margin: 12px 0; display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
  `],
})
export class AuthDemoComponent {
  svc = inject(SecurityModeService);
  private auth = inject(AuthService);

  username = '';
  password = '';
  loading = signal(false);
  result = signal<LoginResponse | null>(null);

  sqliPayloads = ["admin'--", "' OR '1'='1'--", "alice'--"];
  vulnCode = VULN_CODE;
  secureCode = SECURE_CODE;

  login(): void {
    this.loading.set(true);
    this.auth.login(this.username, this.password).subscribe({
      next: (r) => { this.result.set(r); this.loading.set(false); },
      error: () => { this.loading.set(false); },
    });
  }
}
