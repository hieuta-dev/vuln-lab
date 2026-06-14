// FILE: frontend/src/app/core/services/auth.service.ts
// PURPOSE: JWT auth — token stored in memory only (NOT localStorage — security demo)
// SECURITY NOTE: Token cleared on page refresh intentionally; demonstrates ephemeral token storage

import { Injectable, inject, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Router } from '@angular/router';
import { Observable, tap } from 'rxjs';
import { environment } from '../../../environments/environment';

export interface AuthUser { id: string; username: string; role: string; }

export interface LoginResponse {
  success: boolean;
  access_token?: string;
  token_type?: string;
  user?: AuthUser;
  message?: string;
  mode?: string;
}

@Injectable({ providedIn: 'root' })
export class AuthService {
  private http = inject(HttpClient);
  private router = inject(Router);

  // In-memory only — cleared on page refresh (intentional security demo)
  private _token: string | null = null;
  private _user = signal<AuthUser | null>(null);

  readonly currentUser = this._user.asReadonly();
  readonly isLoggedIn = () => !!this._token;

  getToken(): string | null { return this._token; }

  login(username: string, password: string): Observable<LoginResponse> {
    return this.http.post<LoginResponse>(`${environment.apiUrl}/auth/login`, { username, password }).pipe(
      tap(res => {
        if (res.success && res.access_token) {
          this._token = res.access_token;
          this._user.set(res.user ?? null);
        }
      })
    );
  }

  logout(): void {
    if (this._token) {
      this.http.post(`${environment.apiUrl}/auth/logout`, {}).subscribe();
    }
    this._token = null;
    this._user.set(null);
    this.router.navigate(['/login']);
  }

  // Demo-only login that still shows SQLi behavior (used by auth-demo page)
  loginDemo(username: string, password: string): Observable<LoginResponse> {
    return this.http.post<LoginResponse>(`${environment.apiUrl}/auth/login`, { username, password });
  }

  register(username: string, password: string): Observable<LoginResponse> {
    return this.http.post<LoginResponse>(`${environment.apiUrl}/auth/register`, { username, password });
  }

  fetchMe(): void {
    if (!this._token) return;
    this.http.get<AuthUser>(`${environment.apiUrl}/auth/me`).subscribe({
      next: u => this._user.set(u),
      error: () => { this._token = null; this._user.set(null); },
    });
  }
}
