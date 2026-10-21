import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { of } from 'rxjs';
import { DashboardComponent } from './dashboard.component';
import { ThreatLenzApiService } from '../../core/services/api.service';

describe('DashboardComponent', () => {
  let component: DashboardComponent;
  let fixture: ComponentFixture<DashboardComponent>;
  let apiServiceSpy: jasmine.SpyObj<ThreatLenzApiService>;

  beforeEach(async () => {
    apiServiceSpy = jasmine.createSpyObj('ThreatLenzApiService', [
      'getHealth',
      'listRuns',
      'listProfiles',
    ]);

    apiServiceSpy.getHealth.and.returnValue(
      of({
        status: 'healthy',
        database: { status: 'connected', dialect: 'postgresql' },
        app_name: 'ThreatLenz',
        version: '1.0.0',
        timestamp: '2026-10-22T00:00:00Z',
      })
    );

    apiServiceSpy.listRuns.and.returnValue(
      of({
        items: [
          {
            run_id: 'run_test_001',
            report_name: 'ThreatLenz-Test-Report',
            pipeline_version: '1.0.0',
            run_timestamp: '2026-10-22T00:00:00Z',
            execution_duration_seconds: 12.5,
            source_manifest_hash: '22d6470cfb100c00',
            total_profiles: 14,
            attack_categories_count: 13,
            benign_categories_count: 1,
            unknown_categories_count: 0,
            target_impact_status: 'MISSING_EVIDENCE_WITHHELD',
            model_status: 'QUARANTINED_TARGET_LEAKAGE',
            created_at: '2026-10-22T00:00:00Z',
          },
        ],
        total: 1,
        limit: 1,
        offset: 0,
      })
    );

    apiServiceSpy.listProfiles.and.returnValue(
      of({
        items: [
          {
            snapshot_id: 'snap001',
            profile_id: 'prof001',
            run_id: 'run_test_001',
            source_manifest_hash: '22d6470cfb100c00',
            schema_version: '1.0',
            window_type: 'full_campaign',
            window_start: '2018-02-14T00:00:00Z',
            window_end: '2018-03-03T00:00:00Z',
            canonical_label: 'Benign',
            raw_label: 'Benign',
            attack_status: 'BENIGN',
            is_attack: false,
            is_mapped: true,
            flow_count: 6112150,
            total_bytes: 5000000,
            total_packets: 4000000,
            active_observation_units: 8,
            recurrence_denominator: 8,
            recurrence_ratio: 1.0,
            model_reliability: 'HIGH_RELIABILITY',
            created_at: '2026-10-22T00:00:00Z',
          },
        ],
        total: 1,
        limit: 100,
        offset: 0,
      })
    );

    await TestBed.configureTestingModule({
      imports: [DashboardComponent],
      providers: [
        provideRouter([]),
        { provide: ThreatLenzApiService, useValue: apiServiceSpy },
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(DashboardComponent);
    component = fixture.componentInstance;
  });

  it('should create and load dashboard telemetry', () => {
    fixture.detectChanges();
    expect(component).toBeTruthy();
    expect(component.loading).toBeFalse();
    expect(component.health?.status).toBe('healthy');
    expect(component.latestRun?.run_id).toBe('run_test_001');
    expect(component.profiles.length).toBe(1);
  });

  it('should render active run information and evidence safeguard', () => {
    fixture.detectChanges();
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.run-id-pill')?.textContent).toContain('run_test_001');
    expect(compiled.querySelector('.health-status')?.textContent).toContain('Operational');
  });
});
