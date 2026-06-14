// FILE: frontend/src/app/features/login/login.component.ts
// PURPOSE: Login page — polished card, background gradient, always secure bcrypt

import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatButtonModule } from '@angular/material/button';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatIconModule } from '@angular/material/icon';
import { AuthService } from '../../core/services/auth.service';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [FormsModule, MatFormFieldModule, MatInputModule, MatButtonModule,
            MatProgressSpinnerModule, MatIconModule],
  template: `
    <div class="login-bg">
      <div class="login-card">
        <div class="login-logo">
          <span class="logo-icon">🛡️</span>
          <h1 class="logo-title">VulnLab</h1>
          <p class="logo-sub">OWASP Top 10 Security Training Platform</p>
        </div>

        @if (error()) {
          <div class="error-banner">
            <mat-icon>error_outline</mat-icon>
            {{ error() }}
          </div>
        }

        <mat-form-field appearance="outline" class="full-width">
          <mat-label>Username</mat-label>
          <mat-icon matPrefix>person_outline</mat-icon>
          <input matInput [(ngModel)]="username" (keyup.enter)="login()" autocomplete="username" />
        </mat-form-field>

        <mat-form-field appearance="outline" class="full-width">
          <mat-label>Password</mat-label>
          <mat-icon matPrefix>lock_outline</mat-icon>
          <input matInput [type]="showPw() ? 'text' : 'password'" [(ngModel)]="password"
                 (keyup.enter)="login()" autocomplete="current-password" />
          <button mat-icon-button matSuffix (click)="showPw.set(!showPw())" type="button">
            <mat-icon>{{ showPw() ? 'visibility_off' : 'visibility' }}</mat-icon>
          </button>
        </mat-form-field>

        <button class="login-btn" (click)="login()" [disabled]="loading()">
          @if (loading()) {
            <mat-spinner diameter="18" class="btn-spinner"></mat-spinner>
            Signing in…
          } @else {
            Sign In
          }
        </button>

        <p class="hint-text">
          Default accounts: <code>admin / admin123</code> · <code>alice / password</code>
        </p>
      </div>
    </div>
  `,
  styles: [`
    .login-bg {
      min-height: 100vh;
      background: var(--bg-primary);
      background-image:
        radial-gradient(ellipse 60% 50% at 50% -10%, rgba(124,58,237,.18) 0%, transparent 70%),
        repeating-linear-gradient(0deg, transparent, transparent 39px, rgba(255,255,255,.03) 39px, rgba(255,255,255,.03) 40px),
        repeating-linear-gradient(90deg, transparent, transparent 39px, rgba(255,255,255,.03) 39px, rgba(255,255,255,.03) 40px);
      display: flex; align-items: center; justify-content: center;
      padding: 24px;
    }

    .login-card {
      width: 100%; max-width: 400px;
      background: var(--bg-surface);
      border: 1px solid var(--border);
      border-radius: var(--radius-xl);
      padding: 40px 36px;
      box-shadow: 0 24px 64px rgba(0,0,0,.5), 0 0 0 1px rgba(124,58,237,.1);
      animation: fadeIn 0.3s ease;
    }

    .login-logo { text-align: center; margin-bottom: 28px; }
    .logo-icon  { font-size: 44px; display: block; margin-bottom: 8px; }
    .logo-title { font-size: 26px; font-weight: 800; color: var(--accent-light);
                  margin: 0 0 4px; letter-spacing: -0.5px; }
    .logo-sub   { font-size: 13px; color: var(--text-secondary); margin: 0; }

    .error-banner {
      display: flex; align-items: center; gap: 8px;
      background: rgba(239,68,68,.1); border: 1px solid rgba(239,68,68,.3);
      border-radius: var(--radius-md); padding: 10px 14px;
      color: var(--accent-danger); font-size: 13px; margin-bottom: 16px;
    }
    .error-banner mat-icon { font-size: 18px; width: 18px; height: 18px; }

    .full-width { width: 100%; display: block; margin-bottom: 12px; }

    .login-btn {
      width: 100%; height: 44px;
      background: var(--accent); color: white;
      border: none; border-radius: var(--radius-md);
      font-size: 15px; font-weight: 600; cursor: pointer;
      display: flex; align-items: center; justify-content: center; gap: 8px;
      transition: all 0.2s ease; font-family: inherit;
      margin-top: 4px;
    }
    .login-btn:hover:not([disabled]) {
      background: #8b5cf6;
      transform: translateY(-1px);
      box-shadow: 0 8px 24px rgba(124,58,237,.4);
    }
    .login-btn[disabled] { opacity: 0.6; cursor: not-allowed; }
    .btn-spinner { --mdc-circular-progress-active-indicator-color: white !important; }

    .hint-text {
      font-size: 11px; color: var(--text-secondary);
      text-align: center; margin: 14px 0 0;
    }
    .hint-text code { font-size: 11px; }
  `],
})
export class LoginComponent {
  private auth = inject(AuthService);
  private router = inject(Router);

  username = '';
  password = '';
  loading = signal(false);
  error = signal('');
  showPw = signal(false);

  login(): void {
    if (!this.username || !this.password) { this.error.set('Please enter username and password'); return; }
    this.loading.set(true);
    this.error.set('');
    this.auth.login(this.username, this.password).subscribe({
      next: res => {
        this.loading.set(false);
        if (res.success) this.router.navigate(['/dashboard']);
        else this.error.set(res.message ?? 'Invalid credentials');
      },
      error: () => { this.loading.set(false); this.error.set('Login failed. Please try again.'); },
    });
  }
}
