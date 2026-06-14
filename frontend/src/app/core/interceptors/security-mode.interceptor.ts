// FILE: frontend/src/app/core/interceptors/security-mode.interceptor.ts
// PURPOSE: Appends X-Security-Mode header AND Authorization Bearer token to every request

import { HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { SecurityModeService } from '../services/security-mode.service';
import { AuthService } from '../services/auth.service';

export const securityModeInterceptor: HttpInterceptorFn = (req, next) => {
  const svc = inject(SecurityModeService);
  const auth = inject(AuthService);
  const token = auth.getToken();

  const headers: Record<string, string> = { 'X-Security-Mode': svc.currentMode() };
  if (token) headers['Authorization'] = `Bearer ${token}`;

  return next(req.clone({ setHeaders: headers }));
};
