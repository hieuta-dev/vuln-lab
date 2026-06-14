// FILE: frontend/src/app/layouts/auth-layout/auth-layout.component.ts
// PURPOSE: Bare layout for unauthenticated pages — no navbar, just the outlet

import { Component } from '@angular/core';
import { RouterOutlet } from '@angular/router';

@Component({
  selector: 'app-auth-layout',
  standalone: true,
  imports: [RouterOutlet],
  template: `<router-outlet />`,
})
export class AuthLayoutComponent {}
