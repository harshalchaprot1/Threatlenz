import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ThreatLenzApiService } from './api.service';
import { environment } from '../../../environments/environment';

describe('ThreatLenzApiService', () => {
  let service: ThreatLenzApiService;
  let httpTesting: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        ThreatLenzApiService,
        provideHttpClient(),
        provideHttpClientTesting(),
      ],
    });
    service = TestBed.inject(ThreatLenzApiService);
    httpTesting = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpTesting.verify();
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  it('should fetch health status via GET /health', () => {
    const mockHealth = {
      status: 'healthy',
      database: { status: 'connected', dialect: 'postgresql' },
      app_name: 'ThreatLenz',
      version: '1.0.0',
      timestamp: '2026-10-22T00:00:00Z',
    };

    service.getHealth().subscribe((data) => {
      expect(data.status).toBe('healthy');
      expect(data.database.status).toBe('connected');
    });

    const req = httpTesting.expectOne(`${environment.apiUrl}/health`);
    expect(req.request.method).toBe('GET');
    req.flush(mockHealth);
  });

  it('should fetch paginated runs via GET /api/v1/runs with limit and offset', () => {
    const mockRuns = {
      items: [],
      total: 0,
      limit: 10,
      offset: 0,
    };

    service.listRuns(10, 0).subscribe((data) => {
      expect(data.limit).toBe(10);
      expect(data.total).toBe(0);
    });

    const req = httpTesting.expectOne(`${environment.apiUrl}/api/v1/runs?limit=10&offset=0`);
    expect(req.request.method).toBe('GET');
    req.flush(mockRuns);
  });

  it('should fetch threat profiles with filters via GET /api/v1/profiles', () => {
    const mockProfiles = {
      items: [],
      total: 0,
      limit: 20,
      offset: 0,
    };

    service.listProfiles({ attack_status: 'ATTACK', limit: 20 }).subscribe((data) => {
      expect(data.items.length).toBe(0);
    });

    const req = httpTesting.expectOne(`${environment.apiUrl}/api/v1/profiles?attack_status=ATTACK&limit=20`);
    expect(req.request.method).toBe('GET');
    req.flush(mockProfiles);
  });

  it('should fetch TLRS risk assessment via GET /api/v1/profiles/{id}/risk', () => {
    const mockRisk = {
      snapshot_id: 'snap123',
      severity_score: 90,
      frequency_score: 50,
      recurrence_score: 40,
      target_impact_score: null,
      weight_severity: 0.40,
      weight_frequency: 0.25,
      weight_recurrence: 0.20,
      weight_target_impact: 0.15,
      tlrs_complete: null,
      tlrs_complete_rounded: null,
      tlrs_partial_diagnostic: 56.5,
      tlrs_normalized_heuristic: 66.47,
      tlrs_normalized_rounded: 66,
      evidence_coverage: 0.85,
      scoring_status: 'insufficient_evidence',
      risk_band: 'Insufficient Evidence',
      provisional_risk_band: 'DIAGNOSTIC_ONLY: High',
      is_confirmed: false,
      created_at: '2026-10-22T00:00:00Z',
    };

    service.getProfileRisk('snap123').subscribe((risk) => {
      expect(risk.is_confirmed).toBeFalse();
      expect(risk.risk_band).toBe('Insufficient Evidence');
      expect(risk.tlrs_complete).toBeNull();
      expect(risk.evidence_coverage).toBe(0.85);
    });

    const req = httpTesting.expectOne(`${environment.apiUrl}/api/v1/profiles/snap123/risk`);
    expect(req.request.method).toBe('GET');
    req.flush(mockRisk);
  });
});
