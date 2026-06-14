// FILE: frontend/src/app/features/xss-demo/xss-demo.component.ts
// PURPOSE: Comment form demo for XSS vulnerability
// VULNERABLE MODE: renders innerHTML directly (DO NOT use in production)
// SECURE MODE: Angular text binding escapes all HTML automatically

import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { HttpClient } from '@angular/common/http';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatListModule } from '@angular/material/list';
import { DomSanitizer } from '@angular/platform-browser';
import { SecurityModeService } from '../../core/services/security-mode.service';
import { PayloadBadgeComponent } from '../../shared/components/payload-badge/payload-badge.component';
import { AsyncPipe, SlicePipe } from '@angular/common';
import { environment } from '../../../environments/environment';

interface Comment { id: number; content: string; raw_content: string; created_at: string; }

@Component({
  selector: 'app-xss-demo',
  standalone: true,
  imports: [FormsModule, MatFormFieldModule, MatInputModule, MatButtonModule,
            MatCardModule, MatListModule, PayloadBadgeComponent, AsyncPipe, SlicePipe],
  template: `
    <h2>Stored XSS — Comment Demo</h2>
    <p>Mode: <strong [style.color]="(svc.currentMode$ | async) === 'secure' ? '#4caf50' : '#f44336'">
      {{ svc.currentMode$ | async }}
    </strong></p>

    <div class="try-payloads">
      <p>Try these XSS payloads:</p>
      @for (p of xssPayloads; track p) { <app-payload-badge [payload]="p" /> }
    </div>

    <mat-card class="comment-form">
      <mat-card-content>
        <mat-form-field appearance="outline" style="width:100%">
          <mat-label>Add a comment</mat-label>
          <textarea matInput [(ngModel)]="newComment" rows="3"></textarea>
        </mat-form-field>
        <button mat-raised-button color="primary" (click)="postComment()">Post Comment</button>
      </mat-card-content>
    </mat-card>

    <h3>Comments</h3>
    @if ((svc.currentMode$ | async) === 'vulnerable') {
      <p class="warning">⚠ Vulnerable mode: HTML rendered as-is (innerHTML)</p>
    } @else {
      <p class="safe">✓ Secure mode: content escaped via Angular text binding</p>
    }

    <div class="comments-list">
      @for (c of comments(); track c.id) {
        <mat-card class="comment-card">
          <mat-card-content>
            @if ((svc.currentMode$ | async) === 'vulnerable') {
              <!-- VULNERABLE: innerHTML allows XSS execution -->
              <div [innerHTML]="c.content"></div>
            } @else {
              <!-- SECURE: Angular text binding auto-escapes all HTML -->
              <p>{{ c.raw_content }}</p>
            }
            <small>{{ c.created_at | slice:0:19 }}</small>
          </mat-card-content>
        </mat-card>
      }
    </div>
  `,
  styles: [`
    .comment-form { max-width: 600px; margin: 16px 0; }
    .try-payloads { margin: 12px 0; display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
    .warning { color: #f44336; font-size: 13px; }
    .safe { color: #4caf50; font-size: 13px; }
    .comments-list { display: flex; flex-direction: column; gap: 8px; max-width: 600px; }
    .comment-card { background: #1e1e2e; }
    small { color: #888; font-size: 11px; }
  `],
})
export class XssDemoComponent {
  svc = inject(SecurityModeService);
  private http = inject(HttpClient);

  newComment = '';
  comments = signal<Comment[]>([]);
  xssPayloads = ["<script>alert('XSS')</script>", '<img src=x onerror=alert(1)>', '<svg onload=alert(document.cookie)>'];

  constructor() { this.loadComments(); }

  loadComments(): void {
    this.http.get<Comment[]>(`${environment.apiUrl}/comments/`).subscribe(c => this.comments.set(c));
  }

  postComment(): void {
    if (!this.newComment.trim()) return;
    this.http.post(`${environment.apiUrl}/comments/`, { content: this.newComment }).subscribe(() => {
      this.newComment = '';
      this.loadComments();
    });
  }
}
