import { Routes } from '@angular/router';
import { DashboardComponent } from './features/dashboard/dashboard.component';
import { ExplorerComponent } from './features/explorer/explorer.component';
import { ProfileDetailComponent } from './features/profile-detail/profile-detail.component';
import { GovernanceComponent } from './features/governance/governance.component';
import { RunsComponent } from './features/runs/runs.component';

export const routes: Routes = [
  { path: '', redirectTo: 'dashboard', pathMatch: 'full' },
  { path: 'dashboard', component: DashboardComponent, title: 'ThreatLenz — Dashboard' },
  { path: 'profiles', component: ExplorerComponent, title: 'ThreatLenz — Threat Explorer' },
  { path: 'profiles/:id', component: ProfileDetailComponent, title: 'ThreatLenz — Profile Detail' },
  { path: 'governance', component: GovernanceComponent, title: 'ThreatLenz — Model Governance' },
  { path: 'runs', component: RunsComponent, title: 'ThreatLenz — Pipeline Runs' },
  { path: '**', redirectTo: 'dashboard' },
];
