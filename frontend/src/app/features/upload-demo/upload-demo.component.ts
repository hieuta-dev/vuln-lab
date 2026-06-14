// FILE: frontend/src/app/features/upload-demo/upload-demo.component.ts
// PURPOSE: File upload demo — unsafe original-filename save vs. MIME-validated UUID rename

import { Component, inject, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { MatCardModule } from '@angular/material/card';
import { MatButtonModule } from '@angular/material/button';
import { MatListModule } from '@angular/material/list';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { SecurityModeService } from '../../core/services/security-mode.service';
import { AsyncPipe, DecimalPipe } from '@angular/common';
import { environment } from '../../../environments/environment';

@Component({
  selector: 'app-upload-demo',
  standalone: true,
  imports: [MatCardModule, MatButtonModule, MatListModule, MatProgressBarModule, AsyncPipe, DecimalPipe],
  template: `
    <h2>Malicious File Upload Demo</h2>
    <p>Mode: <strong [style.color]="(svc.currentMode$ | async) === 'secure' ? '#4caf50' : '#f44336'">
      {{ svc.currentMode$ | async }}
    </strong></p>

    <mat-card class="upload-card">
      <mat-card-content>
        @if ((svc.currentMode$ | async) === 'vulnerable') {
          <p class="warning">⚠ Vulnerable mode: saves with original filename, no MIME check. Try uploading shell.php</p>
        } @else {
          <p class="safe">✓ Secure mode: MIME type validated via libmagic, file renamed to UUID</p>
        }
        <input type="file" #fileInput (change)="onFileSelect($event)" style="display:none" />
        <button mat-raised-button color="primary" (click)="fileInput.click()">Choose File</button>
        <button mat-raised-button color="accent" (click)="upload()" [disabled]="!selectedFile() || uploading()">
          Upload
        </button>
        @if (selectedFile()) {
          <p>Selected: {{ selectedFile()!.name }} ({{ selectedFile()!.size | number }} bytes)</p>
        }
        @if (uploading()) { <mat-progress-bar mode="indeterminate"></mat-progress-bar> }
      </mat-card-content>
    </mat-card>

    @if (result()) {
      <mat-card [class]="result()!.success ? 'result success' : 'result fail'">
        <mat-card-content>
          @if (result()!.success) {
            <strong>✅ Upload accepted</strong>
            <p>Saved as: {{ result()!.upload?.file_name }}</p>
            <p>MIME: {{ result()!.upload?.mime_type }}</p>
          } @else {
            <strong>❌ Upload rejected</strong>
            <p>{{ result()!.error }}</p>
          }
        </mat-card-content>
      </mat-card>
    }
  `,
  styles: [`
    .upload-card { max-width: 480px; margin: 16px 0; }
    button { margin-right: 8px; }
    .warning { color: #f44336; font-size: 13px; }
    .safe { color: #4caf50; font-size: 13px; }
    .result { max-width: 480px; margin: 12px 0; }
    .success { border-left: 4px solid #4caf50; }
    .fail { border-left: 4px solid #f44336; }
  `],
})
export class UploadDemoComponent {
  svc = inject(SecurityModeService);
  private http = inject(HttpClient);

  selectedFile = signal<File | null>(null);
  uploading = signal(false);
  result = signal<{ success: boolean; upload?: { file_name: string; mime_type: string }; error?: string } | null>(null);

  onFileSelect(event: Event): void {
    const f = (event.target as HTMLInputElement).files?.[0];
    if (f) this.selectedFile.set(f);
  }

  upload(): void {
    const f = this.selectedFile();
    if (!f) return;
    this.uploading.set(true);
    const fd = new FormData();
    fd.append('file', f);
    this.http.post<{ success: boolean; upload?: { file_name: string; mime_type: string }; error?: string }>(
      `${environment.apiUrl}/uploads/`, fd
    ).subscribe({
      next: r => { this.result.set(r); this.uploading.set(false); },
      error: () => { this.uploading.set(false); },
    });
  }
}
