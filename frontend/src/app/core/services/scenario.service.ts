// FILE: frontend/src/app/core/services/scenario.service.ts
// PURPOSE: HTTP calls to the AI scenario generation endpoints

import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../../environments/environment';

export type VulnType =
  | 'sql_injection' | 'xss' | 'csrf' | 'file_upload' | 'broken_auth'
  | 'security_misconfig' | 'sensitive_data_exposure' | 'logging_monitoring'
  | 'supply_chain' | 'cryptographic_failure' | 'insecure_design'
  | 'exceptional_conditions' | 'underprotected_apis';

export interface ScenarioStep {
  step: number;
  phase: string;
  title: string;
  description: string;
  payload?: string;
}

export interface Scenario {
  id?: number;
  title: string;
  vuln_type: VulnType;
  description: string;
  difficulty: 'beginner' | 'intermediate' | 'advanced';
  steps: ScenarioStep[];
  payloads: Array<{ payload: string; description: string; expected_outcome: string }>;
  risk: { cvss_score: number; severity: string; owasp_category: string; impact_summary: string };
  defense_tips: string[];
  code_examples: { vulnerable: string; secure: string };
}

@Injectable({ providedIn: 'root' })
export class ScenarioService {
  private http = inject(HttpClient);

  readonly VULN_TYPES: Array<{ id: VulnType; label: string }> = [
    { id: 'sql_injection',           label: 'SQL Injection' },
    { id: 'xss',                     label: 'Cross-Site Scripting (XSS)' },
    { id: 'csrf',                    label: 'CSRF' },
    { id: 'file_upload',             label: 'Malicious File Upload' },
    { id: 'broken_auth',             label: 'Broken Authentication' },
    { id: 'security_misconfig',      label: 'Security Misconfiguration' },
    { id: 'sensitive_data_exposure', label: 'Sensitive Data Exposure' },
    { id: 'logging_monitoring',      label: 'Insufficient Logging & Monitoring' },
    { id: 'supply_chain',            label: 'Software Supply Chain Failures' },
    { id: 'cryptographic_failure',   label: 'Cryptographic Failures' },
    { id: 'insecure_design',         label: 'Insecure Design' },
    { id: 'exceptional_conditions',  label: 'Mishandling Exceptional Conditions' },
    { id: 'underprotected_apis',     label: 'Underprotected APIs' },
  ];

  generate(vulnType: VulnType, difficulty = 'beginner'): Observable<Scenario> {
    return this.http.post<Scenario>(`${environment.apiUrl}/scenarios/generate`, {
      vuln_type: vulnType,
      difficulty,
    });
  }

  list(): Observable<Scenario[]> {
    return this.http.get<Scenario[]>(`${environment.apiUrl}/scenarios/`);
  }

  get(id: number): Observable<Scenario> {
    return this.http.get<Scenario>(`${environment.apiUrl}/scenarios/${id}`);
  }
}
