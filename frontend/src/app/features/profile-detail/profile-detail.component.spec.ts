import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { provideNoopAnimations } from '@angular/platform-browser/animations';
import { of } from 'rxjs';
import { ProfileDetailComponent } from './profile-detail.component';
import { ThreatLenzApiService } from '../../core/services/api.service';

describe('ProfileDetailComponent', () => {
  let component: ProfileDetailComponent;
  let fixture: ComponentFixture<ProfileDetailComponent>;
  let apiServiceSpy: jasmine.SpyObj<ThreatLenzApiService>;

  beforeEach(async () => {
    apiServiceSpy = jasmine.createSpyObj('ThreatLenzApiService', [
      'getProfileDetail',
      'getProfileRisk',
      'getProfileMitre',
      'getProfileAdvisories',
    ]);

    apiServiceSpy.getProfileDetail.and.returnValue(
      of({
        snapshot_id: 'snap_ddos_01',
        profile_id: 'prof_ddos_01',
        run_id: 'run_001',
        source_manifest_hash: '22d6470cfb100c00',
        schema_version: '1.0',
        window_type: 'full_campaign',
        window_start: '2018-02-14T00:00:00Z',
        window_end: '2018-03-03T00:00:00Z',
        canonical_label: 'DDoS-HOIC',
        raw_label: 'DDOS attack-HOIC',
        attack_status: 'ATTACK',
        is_attack: true,
        is_mapped: true,
        flow_count: 686012,
        total_bytes: 84000000,
        total_packets: 1200000,
        active_observation_units: 1,
        recurrence_denominator: 8,
        recurrence_ratio: 0.125,
        model_reliability: 'HIGH_RELIABILITY',
        created_at: '2026-10-22T00:00:00Z',
      })
    );

    apiServiceSpy.getProfileRisk.and.returnValue(
      of({
        snapshot_id: 'snap_ddos_01',
        severity_score: 75,
        frequency_score: 97.2,
        recurrence_score: 12.5,
        target_impact_score: null,
        weight_severity: 0.40,
        weight_frequency: 0.25,
        weight_recurrence: 0.20,
        weight_target_impact: 0.15,
        tlrs_complete: null,
        tlrs_complete_rounded: null,
        tlrs_partial_diagnostic: 56.8,
        tlrs_normalized_heuristic: 66.82,
        tlrs_normalized_rounded: 67,
        evidence_coverage: 0.85,
        scoring_status: 'insufficient_evidence',
        risk_band: 'Insufficient Evidence',
        provisional_risk_band: 'DIAGNOSTIC_ONLY: High',
        is_confirmed: false,
        created_at: '2026-10-22T00:00:00Z',
      })
    );

    apiServiceSpy.getProfileMitre.and.returnValue(
      of({
        snapshot_id: 'snap_ddos_01',
        canonical_label: 'DDoS-HOIC',
        technique_id: 'T1498.001',
        technique_name: 'Network Denial of Service: Direct Network Flood',
        tactic: 'Impact',
        mapping_status: 'candidate',
        is_confirmed: false,
        rationale: 'Direct UDP/TCP flood patterns observable in Netflow aggregations.',
        missing_telemetry: ['Upstream link saturation metrics'],
        created_at: '2026-10-22T00:00:00Z',
      })
    );

    apiServiceSpy.getProfileAdvisories.and.returnValue(
      of({
        snapshot_id: 'snap_ddos_01',
        total: 1,
        items: [
          {
            id: 1,
            snapshot_id: 'snap_ddos_01',
            recommendation_id: 'REC_DDOS_01',
            threat_category: 'DDoS-HOIC',
            priority: 'HIGH',
            action_type: 'Rate Limiting Review',
            summary: 'Review border router rate limiting policies',
            detailed_guidance: 'Inspect ingress packet volumes.',
            missing_evidence_required: [],
            analyst_validation_required: true,
            is_automated_action: false,
            created_at: '2026-10-22T00:00:00Z',
          },
        ],
      })
    );

    await TestBed.configureTestingModule({
      imports: [ProfileDetailComponent],
      providers: [
        provideRouter([]),
        provideNoopAnimations(),
        { provide: ThreatLenzApiService, useValue: apiServiceSpy },
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(ProfileDetailComponent);
    component = fixture.componentInstance;
    component.id = 'snap_ddos_01';
  });

  it('should load profile detail, risk, mitre, and advisories', () => {
    fixture.detectChanges();
    expect(component).toBeTruthy();
    expect(component.profile?.canonical_label).toBe('DDoS-HOIC');
    expect(component.risk?.is_confirmed).toBeFalse();
    expect(component.mitre?.technique_id).toBe('T1498.001');
    expect(component.advisories.length).toBe(1);
  });

  it('should preserve withheld status when target impact is missing', () => {
    fixture.detectChanges();
    expect(component.risk?.is_confirmed).toBeFalse();
    expect(component.risk?.risk_band).toBe('Insufficient Evidence');
    expect(component.risk?.provisional_risk_band).toBe('DIAGNOSTIC_ONLY: High');
  });
});
