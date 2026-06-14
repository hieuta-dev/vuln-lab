// FILE: frontend/src/app/core/services/scan.service.ts
// PURPOSE: HTTP calls to scan API endpoints

import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../../environments/environment';

export interface ScanResult {
  id: number;
  vuln_type: string;
  status: 'scanning' | 'success' | 'passed' | 'failed' | 'needs_info';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info' | null;
  missing_info: string | null;
  findings: { summary: string; detail?: string; scenario?: Record<string, unknown> } | null;
  reproduce_steps: string[] | null;
  scenario_id: number | null;
  scanned_at: string;
}

export interface ScanSession {
  id: number;
  target_id: number;
  target_name: string;
  target_url: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  started_at: string;
  completed_at: string | null;
  severity_counts: Record<string, number>;
  total_results: number;
}

export interface SessionDetail {
  session: { id: number; status: string; started_at: string; completed_at: string | null };
  target: { id: number; target_name: string; target_url: string; description: string | null };
  results: ScanResult[];
}

export interface LiveResults {
  session_status: string;
  completed: number;
  total: number;
  results: ScanResult[];
}

@Injectable({ providedIn: 'root' })
export class ScanService {
  private http = inject(HttpClient);

  startScan(body: {
    target_url: string; target_name: string; description?: string;
    auth_info?: Record<string, string> | null; headers?: { key: string; value: string }[];
  }): Observable<{ session_id: number; target_id: number; status: string }> {
    return this.http.post<{ session_id: number; target_id: number; status: string }>(
      `${environment.apiUrl}/scans/start`, body
    );
  }

  getSessions(): Observable<ScanSession[]> {
    return this.http.get<ScanSession[]>(`${environment.apiUrl}/scans/sessions`);
  }

  getSession(id: number): Observable<SessionDetail> {
    return this.http.get<SessionDetail>(`${environment.apiUrl}/scans/sessions/${id}`);
  }

  getResults(id: number): Observable<LiveResults> {
    return this.http.get<LiveResults>(`${environment.apiUrl}/scans/sessions/${id}/results`);
  }

  provideInfo(sessionId: number, vuln_type: string, additional_info: string): Observable<unknown> {
    return this.http.post(
      `${environment.apiUrl}/scans/sessions/${sessionId}/provide-info`,
      { vuln_type, additional_info }
    );
  }

  deleteSession(id: number): Observable<unknown> {
    return this.http.delete(`${environment.apiUrl}/scans/sessions/${id}`);
  }

  getPdfUrl(id: number): string {
    return `${environment.apiUrl}/scans/sessions/${id}/export-pdf`;
  }
}
