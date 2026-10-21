import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule, RouterOutlet } from '@angular/router';
import { MatToolbarModule } from '@angular/material/toolbar';
import { MatSidenavModule } from '@angular/material/sidenav';
import { MatListModule } from '@angular/material/list';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatChipsModule } from '@angular/material/chips';
import { environment } from '../environments/environment';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [
    CommonModule,
    RouterModule,
    RouterOutlet,
    MatToolbarModule,
    MatSidenavModule,
    MatListModule,
    MatIconModule,
    MatButtonModule,
    MatChipsModule,
  ],
  templateUrl: './app.component.html',
  styleUrl: './app.component.scss',
})
export class AppComponent {
  readonly title = 'ThreatLenz';
  readonly version = environment.version;
  readonly apiUrl = environment.apiUrl;

  navItems = [
    { label: 'Overview', route: '/dashboard', icon: 'dashboard' },
    { label: 'Threat Explorer', route: '/profiles', icon: 'security' },
    { label: 'Model Governance', route: '/governance', icon: 'verified_user' },
    { label: 'Pipeline Runs', route: '/runs', icon: 'history' },
  ];
}
