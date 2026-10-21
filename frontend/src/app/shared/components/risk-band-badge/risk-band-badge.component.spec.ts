import { ComponentFixture, TestBed } from '@angular/core/testing';
import { RiskBandBadgeComponent } from './risk-band-badge.component';

describe('RiskBandBadgeComponent', () => {
  let component: RiskBandBadgeComponent;
  let fixture: ComponentFixture<RiskBandBadgeComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [RiskBandBadgeComponent],
    }).compileComponents();

    fixture = TestBed.createComponent(RiskBandBadgeComponent);
    component = fixture.componentInstance;
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should display Insufficient Evidence when isConfirmed is false', () => {
    component.isConfirmed = false;
    component.riskBand = 'High';
    component.provisionalBand = 'DIAGNOSTIC_ONLY: High';
    fixture.detectChanges();

    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.band-withheld')).toBeTruthy();
    expect(compiled.textContent).toContain('Insufficient Evidence');
  });

  it('should display confirmed risk band when isConfirmed is true', () => {
    component.isConfirmed = true;
    component.riskBand = 'Critical';
    fixture.detectChanges();

    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.band-critical')).toBeTruthy();
    expect(compiled.textContent).toContain('Critical');
  });
});
