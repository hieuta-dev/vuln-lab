import { Routes } from '@angular/router';
import { authGuard } from './core/guards/auth.guard';
import { guestGuard } from './core/guards/guest.guard';
import { AuthLayoutComponent } from './layouts/auth-layout/auth-layout.component';
import { AppLayoutComponent } from './layouts/app-layout/app-layout.component';

export const routes: Routes = [
  // Unauthenticated shell — no navbar
  {
    path: 'login',
    component: AuthLayoutComponent,
    canActivate: [guestGuard],
    children: [
      {
        path: '',
        loadComponent: () => import('./features/login/login.component').then(m => m.LoginComponent),
      },
    ],
  },

  // Authenticated shell — navbar + mode toggle
  {
    path: '',
    component: AppLayoutComponent,
    canActivate: [authGuard],
    children: [
      { path: '', redirectTo: 'dashboard', pathMatch: 'full' },
      {
        path: 'dashboard',
        loadComponent: () => import('./features/dashboard/dashboard.component').then(m => m.DashboardComponent),
      },
      {
        path: 'auth-demo',
        loadComponent: () => import('./features/auth-demo/auth-demo.component').then(m => m.AuthDemoComponent),
      },
      {
        path: 'xss-demo',
        loadComponent: () => import('./features/xss-demo/xss-demo.component').then(m => m.XssDemoComponent),
      },
      {
        path: 'upload-demo',
        loadComponent: () => import('./features/upload-demo/upload-demo.component').then(m => m.UploadDemoComponent),
      },
      {
        path: 'csrf-demo',
        loadComponent: () => import('./features/csrf-demo/csrf-demo.component').then(m => m.CsrfDemoComponent),
      },
      {
        path: 'scenario-lab',
        loadComponent: () => import('./features/scenario-lab/scenario-lab.component').then(m => m.ScenarioLabComponent),
      },
      {
        path: 'scan/new',
        loadComponent: () => import('./features/scan/new-scan/new-scan.component').then(m => m.NewScanComponent),
      },
      {
        path: 'scan/session/:id',
        loadComponent: () => import('./features/scan/session/scan-session.component').then(m => m.ScanSessionComponent),
      },
      {
        path: 'scan/history',
        loadComponent: () => import('./features/scan/history/scan-history.component').then(m => m.ScanHistoryComponent),
      },
    ],
  },

  { path: '**', redirectTo: 'dashboard' },
];
