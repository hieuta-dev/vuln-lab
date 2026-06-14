// FILE: frontend/src/app/core/guards/guest.guard.ts
// PURPOSE: Prevents logged-in users from visiting /login — redirects to /dashboard

import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { AuthService } from '../services/auth.service';

export const guestGuard: CanActivateFn = () => {
  const auth = inject(AuthService);
  if (!auth.isLoggedIn()) return true;
  inject(Router).navigate(['/dashboard']);
  return false;
};
