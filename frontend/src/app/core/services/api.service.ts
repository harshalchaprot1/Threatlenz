import { Injectable } from '@angular/core';
import { HttpClient, HttpErrorResponse, HttpParams } from '@angular/common/http';
import { Observable, throwError } from 'rxjs';
import { catchError } from 'rxjs/operators';
import { environment } from '../../../environments/environment';
import {
  AdvisoriesListResponse,
  HealthResponse,
  MitreMappingResponse,
  PaginatedResponse,
  PipelineRunDetail,
  PipelineRunSummary,
  ProfileFilterParams,
  RiskAssessmentResponse,
  ServiceMetadata,
  ThreatProfileSummary,
} from '../models';

@Injectable({
  providedIn: 'root',
})
export class ThreatLenzApiService {
  private readonly baseUrl = environment.apiUrl.replace(/\/+$/, '');

  constructor(private readonly http: HttpClient) {}

  /**
   * Root service metadata endpoint.
   */
  getServiceMetadata(): Observable<ServiceMetadata> {
    return this.http
      .get<ServiceMetadata>(`${this.baseUrl}/`)
      .pipe(catchError(this.handleError));
  }

  /**
   * System and database connectivity health check.
   */
  getHealth(): Observable<HealthResponse> {
    return this.http
      .get<HealthResponse>(`${this.baseUrl}/health`)
      .pipe(catchError(this.handleError));
  }

  /**
   * Paginated list of pipeline execution runs.
   */
  listRuns(limit: number = 20, offset: number = 0): Observable<PaginatedResponse<PipelineRunSummary>> {
    let params = new HttpParams()
      .set('limit', limit.toString())
      .set('offset', offset.toString());

    return this.http
      .get<PaginatedResponse<PipelineRunSummary>>(`${this.baseUrl}/api/v1/runs`, { params })
      .pipe(catchError(this.handleError));
  }

  /**
   * Detailed metadata, provenance, and governance for a specific pipeline execution run.
   */
  getRunDetail(runId: string): Observable<PipelineRunDetail> {
    return this.http
      .get<PipelineRunDetail>(`${this.baseUrl}/api/v1/runs/${encodeURIComponent(runId)}`)
      .pipe(catchError(this.handleError));
  }

  /**
   * Paginated list of threat profile snapshots with optional filters.
   */
  listProfiles(filterParams?: ProfileFilterParams): Observable<PaginatedResponse<ThreatProfileSummary>> {
    let params = new HttpParams();

    if (filterParams) {
      if (filterParams.run_id) {
        params = params.set('run_id', filterParams.run_id);
      }
      if (filterParams.canonical_label) {
        params = params.set('canonical_label', filterParams.canonical_label);
      }
      if (filterParams.attack_status) {
        params = params.set('attack_status', filterParams.attack_status);
      }
      if (filterParams.is_attack !== undefined && filterParams.is_attack !== null) {
        params = params.set('is_attack', filterParams.is_attack.toString());
      }
      if (filterParams.limit !== undefined) {
        params = params.set('limit', filterParams.limit.toString());
      }
      if (filterParams.offset !== undefined) {
        params = params.set('offset', filterParams.offset.toString());
      }
    }

    return this.http
      .get<PaginatedResponse<ThreatProfileSummary>>(`${this.baseUrl}/api/v1/profiles`, { params })
      .pipe(catchError(this.handleError));
  }

  /**
   * Individual threat profile snapshot by its unique snapshot_id.
   */
  getProfileDetail(snapshotId: string): Observable<ThreatProfileSummary> {
    return this.http
      .get<ThreatProfileSummary>(`${this.baseUrl}/api/v1/profiles/${encodeURIComponent(snapshotId)}`)
      .pipe(catchError(this.handleError));
  }

  /**
   * TLRS risk assessment details associated with a threat profile snapshot.
   */
  getProfileRisk(snapshotId: string): Observable<RiskAssessmentResponse> {
    return this.http
      .get<RiskAssessmentResponse>(`${this.baseUrl}/api/v1/profiles/${encodeURIComponent(snapshotId)}/risk`)
      .pipe(catchError(this.handleError));
  }

  /**
   * MITRE ATT&CK technique mapping for a threat profile snapshot.
   */
  getProfileMitre(snapshotId: string): Observable<MitreMappingResponse> {
    return this.http
      .get<MitreMappingResponse>(`${this.baseUrl}/api/v1/profiles/${encodeURIComponent(snapshotId)}/mitre`)
      .pipe(catchError(this.handleError));
  }

  /**
   * Actionable defensive advisories linked to a threat profile snapshot.
   */
  getProfileAdvisories(snapshotId: string): Observable<AdvisoriesListResponse> {
    return this.http
      .get<AdvisoriesListResponse>(`${this.baseUrl}/api/v1/profiles/${encodeURIComponent(snapshotId)}/advisories`)
      .pipe(catchError(this.handleError));
  }

  /**
   * Standard error normalizer extracting backend detail strings without leaking secrets.
   */
  private handleError(error: HttpErrorResponse): Observable<never> {
    let errorMessage = 'An unexpected network error occurred. Please check backend connectivity.';

    if (error.error instanceof ErrorEvent) {
      // Client-side / network failure
      errorMessage = `Client error: ${error.error.message}`;
    } else {
      // Backend returned HTTP error status
      if (error.error && typeof error.error === 'object' && 'detail' in error.error) {
        errorMessage = String(error.error.detail);
      } else if (error.status === 0) {
        errorMessage = 'Unable to connect to ThreatLenz backend at ' + environment.apiUrl + '. Is the server running?';
      } else if (error.status === 404) {
        errorMessage = 'Requested resource was not found on the server.';
      } else if (error.status === 503) {
        errorMessage = 'ThreatLenz service is currently degraded (Database disconnected).';
      } else {
        errorMessage = `Server returned status code ${error.status}: ${error.statusText || 'Error'}`;
      }
    }

    return throwError(() => new Error(errorMessage));
  }
}
