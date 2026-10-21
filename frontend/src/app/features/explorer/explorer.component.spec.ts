import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { provideNoopAnimations } from '@angular/platform-browser/animations';
import { of } from 'rxjs';
import { ExplorerComponent } from './explorer.component';
import { ThreatLenzApiService } from '../../core/services/api.service';

describe('ExplorerComponent', () => {
  let component: ExplorerComponent;
  let fixture: ComponentFixture<ExplorerComponent>;
  let apiServiceSpy: jasmine.SpyObj<ThreatLenzApiService>;

  beforeEach(async () => {
    apiServiceSpy = jasmine.createSpyObj('ThreatLenzApiService', ['listProfiles']);

    apiServiceSpy.listProfiles.and.returnValue(
      of({
        items: [
          {
            snapshot_id: 'snap_bot_01',
            profile_id: 'prof_bot_01',
            run_id: 'run_001',
            source_manifest_hash: '22d6470cfb100c00',
            schema_version: '1.0',
            window_type: 'full_campaign',
            window_start: '2018-02-14T00:00:00Z',
            window_end: '2018-03-03T00:00:00Z',
            canonical_label: 'Bot',
            raw_label: 'Bot',
            attack_status: 'ATTACK',
            is_attack: true,
            is_mapped: true,
            flow_count: 143012,
            total_bytes: 1200000,
            total_packets: 900000,
            active_observation_units: 1,
            recurrence_denominator: 8,
            recurrence_ratio: 0.125,
            model_reliability: 'HIGH_RELIABILITY',
            created_at: '2026-10-22T00:00:00Z',
          },
        ],
        total: 1,
        limit: 20,
        offset: 0,
      })
    );

    await TestBed.configureTestingModule({
      imports: [ExplorerComponent],
      providers: [
        provideRouter([]),
        provideNoopAnimations(),
        { provide: ThreatLenzApiService, useValue: apiServiceSpy },
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(ExplorerComponent);
    component = fixture.componentInstance;
  });

  it('should create and load threat profiles', () => {
    fixture.detectChanges();
    expect(component).toBeTruthy();
    expect(component.profiles.length).toBe(1);
    expect(component.totalCount).toBe(1);
  });

  it('should query with filter when search category changes', () => {
    fixture.detectChanges();
    component.searchCategory = 'Bot';
    component.onSearchChange();

    expect(apiServiceSpy.listProfiles).toHaveBeenCalledWith(
      jasmine.objectContaining({
        canonical_label: 'Bot',
        limit: 20,
        offset: 0,
      })
    );
  });
});
