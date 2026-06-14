// FILE: frontend/src/app/layouts/app-layout/app-layout.component.ts
// PURPOSE: Authenticated shell — navbar + mode toggle + router outlet

import { Component, inject } from '@angular/core';
import { RouterOutlet, RouterLink, RouterLinkActive } from '@angular/router';
import { MatButtonModule } from '@angular/material/button';
import { MatMenuModule } from '@angular/material/menu';
import { MatIconModule } from '@angular/material/icon';
import { MatDividerModule } from '@angular/material/divider';
import { MatTooltipModule } from '@angular/material/tooltip';
import { ModeToggleComponent } from '../../shared/components/mode-toggle/mode-toggle.component';
import { AuthService } from '../../core/services/auth.service';

@Component({
  selector: 'app-app-layout',
  standalone: true,
  imports: [RouterOutlet, RouterLink, RouterLinkActive, MatButtonModule,
            MatMenuModule, MatIconModule, MatTooltipModule, MatDividerModule, ModeToggleComponent],
  template: `
    <header class="navbar">
      <div class="navbar-inner">
        <a class="brand" routerLink="/dashboard">
          <span class="brand-icon">🛡️</span>
          <span class="brand-text">VulnLab</span>
        </a>

        <nav class="nav-links">
          <a class="nav-link" routerLink="/dashboard" routerLinkActive="nav-link--active">
            Dashboard
          </a>

          <button class="nav-link nav-link--menu" [matMenuTriggerFor]="scanMenu">
            Scan
            <mat-icon class="dropdown-icon">expand_more</mat-icon>
          </button>
          <mat-menu #scanMenu="matMenu">
            <a mat-menu-item routerLink="/scan/new">
              <mat-icon>add_circle_outline</mat-icon> New Scan
            </a>
            <a mat-menu-item routerLink="/scan/history">
              <mat-icon>history</mat-icon> Scan History
            </a>
          </mat-menu>

          <a class="nav-link" routerLink="/auth-demo" routerLinkActive="nav-link--active">SQL Injection</a>
          <a class="nav-link" routerLink="/xss-demo" routerLinkActive="nav-link--active">XSS</a>
          <a class="nav-link" routerLink="/upload-demo" routerLinkActive="nav-link--active">File Upload</a>
          <a class="nav-link" routerLink="/csrf-demo" routerLinkActive="nav-link--active">CSRF</a>
          <a class="nav-link" routerLink="/scenario-lab" routerLinkActive="nav-link--active">Scenario Lab</a>
        </nav>

        <div class="navbar-right">
          <app-mode-toggle />

          @if (auth.currentUser()) {
            <button class="user-chip" [matMenuTriggerFor]="userMenu">
              <span class="user-avatar">{{ auth.currentUser()!.username[0].toUpperCase() }}</span>
              <span class="user-name">{{ auth.currentUser()!.username }}</span>
              <mat-icon class="dropdown-icon">expand_more</mat-icon>
            </button>
            <mat-menu #userMenu="matMenu">
              <div class="user-menu-header">
                <span class="um-username">{{ auth.currentUser()!.username }}</span>
                <span class="um-role">{{ auth.currentUser()!.role }}</span>
              </div>
              <mat-divider></mat-divider>
              <button mat-menu-item class="logout-item" (click)="auth.logout()">
                <mat-icon>logout</mat-icon> Sign Out
              </button>
            </mat-menu>
          }
        </div>
      </div>
    </header>

    <main class="page-content">
      <router-outlet />
    </main>
  `,
  styles: [`
    .navbar {
      position: sticky; top: 0; z-index: 100; height: 56px;
      background: var(--bg-surface);
      border-bottom: 1px solid var(--border);
      backdrop-filter: blur(12px);
    }
    .navbar-inner {
      max-width: 1440px; margin: 0 auto;
      height: 100%; display: flex; align-items: center;
      padding: 0 20px; gap: 8px;
    }

    .brand {
      display: flex; align-items: center; gap: 8px;
      font-size: 17px; font-weight: 800; color: var(--accent-light);
      text-decoration: none; margin-right: 12px;
    }
    .brand-icon { font-size: 20px; }
    .brand-text { letter-spacing: -0.3px; }

    .nav-links { display: flex; align-items: center; gap: 2px; flex: 1; }

    .nav-link {
      display: inline-flex; align-items: center; gap: 4px;
      padding: 6px 12px; border-radius: var(--radius-xl);
      font-size: 13px; font-weight: 500;
      color: var(--text-secondary); text-decoration: none;
      background: none; border: none; cursor: pointer;
      transition: all 0.15s ease; white-space: nowrap;
      font-family: inherit;
    }
    .nav-link:hover, .nav-link--active {
      color: var(--text-primary);
      background: var(--bg-elevated);
    }
    .nav-link--active { color: var(--accent-light) !important; }
    .nav-link--menu { display: inline-flex; align-items: center; }
    .dropdown-icon { font-size: 16px !important; width: 16px !important; height: 16px !important; }

    .navbar-right { display: flex; align-items: center; gap: 8px; }

    .user-chip {
      display: inline-flex; align-items: center; gap: 8px;
      padding: 4px 10px 4px 4px; border-radius: var(--radius-xl);
      background: var(--bg-elevated); border: 1px solid var(--border);
      color: var(--text-primary); cursor: pointer; font-family: inherit;
      font-size: 13px; font-weight: 500;
      transition: all 0.15s ease;
    }
    .user-chip:hover { border-color: var(--accent); background: var(--bg-elevated); }

    .user-avatar {
      width: 24px; height: 24px; border-radius: 50%;
      background: var(--accent); color: white;
      display: flex; align-items: center; justify-content: center;
      font-size: 11px; font-weight: 700;
    }
    .user-name { max-width: 120px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

    .user-menu-header {
      padding: 12px 16px; display: flex; flex-direction: column;
    }
    .um-username { font-weight: 600; font-size: 14px; color: var(--text-primary); }
    .um-role { font-size: 11px; color: var(--accent-light); text-transform: uppercase; letter-spacing: 0.05em; }

    ::ng-deep .logout-item .mat-icon { color: var(--accent-danger) !important; }
    ::ng-deep .logout-item { color: var(--accent-danger) !important; }
  `],
})
export class AppLayoutComponent {
  auth = inject(AuthService);
}
