import { ComponentFixture, TestBed } from '@angular/core/testing';
import { EvidenceBannerComponent } from './evidence-banner.component';

describe('EvidenceBannerComponent', () => {
  let component: EvidenceBannerComponent;
  let fixture: ComponentFixture<EvidenceBannerComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [EvidenceBannerComponent],
    }).compileComponents();

    fixture = TestBed.createComponent(EvidenceBannerComponent);
    component = fixture.componentInstance;
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should render alert and withheld warning when isConfirmed is false', () => {
    component.isConfirmed = false;
    component.evidenceCoverage = 0.85;
    component.provisionalRiskBand = 'DIAGNOSTIC_ONLY: High';
    fixture.detectChanges();

    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.alert-title')?.textContent).toContain('Operational Risk Score Withheld');
    expect(compiled.querySelector('.coverage-pill')?.textContent).toContain('85.0% Evidence Coverage');
    expect(compiled.querySelector('.diagnostic-val')?.textContent).toContain('DIAGNOSTIC_ONLY: High');
  });

  it('should render confirmed operational notice when isConfirmed is true', () => {
    component.isConfirmed = true;
    fixture.detectChanges();

    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.confirmed-title')?.textContent).toContain('Confirmed Operational Evidence');
  });
});
