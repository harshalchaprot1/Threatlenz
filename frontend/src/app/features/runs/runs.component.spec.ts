import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideNoopAnimations } from '@angular/platform-browser/animations';
import { of } from 'rxjs';
import { RunsComponent } from './runs.component';
import { ThreatLenzApiService } from '../../core/services/api.service';

describe('RunsComponent', () => {
  let component: RunsComponent;
  let fixture: ComponentFixture<RunsComponent>;
  let apiServiceSpy: jasmine.SpyObj<ThreatLenzApiService>;

  beforeEach(async () => {
    apiServiceSpy = jasmine.createSpyObj('ThreatLenzApiService', ['listRuns', 'getRunDetail']);

    apiServiceSpy.listRuns.and.returnValue(
      of({
        items: [
          {
            run_id: 'run_20261014_01',
            report_name: 'ThreatLenz-Report',
            pipeline_version: '1.0.0',
            run_timestamp: '2026-10-14T01:30:00Z',
            execution_duration_seconds: 11.8,
            source_manifest_hash: '22d6470cfb100c00',
            total_profiles: 14,
            attack_categories_count: 13,
            benign_categories_count: 1,
            unknown_categories_count: 0,
            target_impact_status: 'MISSING_EVIDENCE_WITHHELD',
            model_status: 'QUARANTINED_TARGET_LEAKAGE',
            created_at: '2026-10-14T01:30:00Z',
          },
        ],
        total: 1,
        limit: 20,
        offset: 0,
      })
    );

    await TestBed.configureTestingModule({
      imports: [RunsComponent],
      providers: [
        provideNoopAnimations(),
        { provide: ThreatLenzApiService, useValue: apiServiceSpy },
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(RunsComponent);
    component = fixture.componentInstance;
  });

  it('should create and load pipeline runs', () => {
    fixture.detectChanges();
    expect(component).toBeTruthy();
    expect(component.runs.length).toBe(1);
    expect(component.runs[0].run_id).toBe('run_20261014_01');
  });

  it('should format bytes correctly', () => {
    expect(component.formatBytes(1048576)).toBe('1 MB');
    expect(component.formatBytes(0)).toBe('0 Bytes');
  });
});
