import { ComponentFixture, TestBed } from '@angular/core/testing';
import { StatusBadgeComponent } from './status-badge.component';

describe('StatusBadgeComponent', () => {
  let component: StatusBadgeComponent;
  let fixture: ComponentFixture<StatusBadgeComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [StatusBadgeComponent],
    }).compileComponents();

    fixture = TestBed.createComponent(StatusBadgeComponent);
    component = fixture.componentInstance;
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should render ATTACK status chip', () => {
    component.status = 'ATTACK';
    fixture.detectChanges();
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.chip-attack')).toBeTruthy();
    expect(compiled.textContent).toContain('ATTACK');
  });

  it('should render BENIGN status chip', () => {
    component.status = 'BENIGN';
    fixture.detectChanges();
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.chip-benign')).toBeTruthy();
    expect(compiled.textContent).toContain('BENIGN');
  });

  it('should default to UNKNOWN when status is null or unrecognized', () => {
    component.status = null;
    fixture.detectChanges();
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.chip-unknown')).toBeTruthy();
    expect(compiled.textContent).toContain('UNKNOWN');
  });
});
