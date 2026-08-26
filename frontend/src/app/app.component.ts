import { CommonModule } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { Component, OnDestroy, OnInit, inject } from '@angular/core';

interface Features {
  packets_per_sec: number;
  bytes_per_sec: number;
  connections_per_sec: number;
  http_requests_per_sec: number;
  avg_packet_size: number;
  min_packet_size: number;
  max_packet_size: number;
  packet_size_std: number;
}

interface Detection {
  timestamp: string;
  status: 'NORMAL' | 'ANOMALY' | 'NO TRAFFIC';
  prediction: number | null;
  normal_probability: number | null;
  anomaly_probability: number | null;
  features: Features | null;
  server_ip?: string;
  interface?: string;
  client_ips?: string[];
}

@Component({
  selector: 'sf-root',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './app.component.html',
  styleUrl: './app.component.css'
})
export class AppComponent implements OnInit, OnDestroy {
  private readonly http = inject(HttpClient);
  private timer?: ReturnType<typeof setInterval>;
  detection: Detection | null = null;
  lastTraffic: Detection | null = null;
  loading = true;
  error = '';

  readonly featureRows: Array<{ key: keyof Features; label: string; unit: string }> = [
    { key: 'packets_per_sec', label: 'Packets / sec', unit: 'pps' },
    { key: 'bytes_per_sec', label: 'Bytes / sec', unit: 'B/s' },
    { key: 'connections_per_sec', label: 'Connections / sec', unit: 'cps' },
    { key: 'http_requests_per_sec', label: 'HTTP requests / sec', unit: 'req/s' },
    { key: 'avg_packet_size', label: 'Average packet size', unit: 'bytes' },
    { key: 'min_packet_size', label: 'Minimum packet size', unit: 'bytes' },
    { key: 'max_packet_size', label: 'Maximum packet size', unit: 'bytes' },
    { key: 'packet_size_std', label: 'Packet size std. dev.', unit: 'bytes' }
  ];

  ngOnInit(): void {
    this.refresh();
    this.timer = setInterval(() => this.refresh(), 2000);
  }

  ngOnDestroy(): void {
    if (this.timer) clearInterval(this.timer);
  }

  refresh(): void {
    this.http.get<Detection>('/api/detection').subscribe({
      next: (result) => {
        this.detection = result;
        if (result.status !== 'NO TRAFFIC') {
          this.lastTraffic = result;
        }
        this.error = '';
        this.loading = false;
      },
      error: () => {
        this.error = 'Detection API unavailable';
        this.loading = false;
      }
    });
  }

  get statusClass(): string {
    return (this.detection?.status ?? 'NO TRAFFIC').toLowerCase().replace(' ', '-');
  }

  formatValue(value: number | null | undefined): string {
    return value === null || value === undefined ? '--' : value.toLocaleString('en-US', { maximumFractionDigits: 2 });
  }

  percent(value: number | null | undefined): string {
    return value === null || value === undefined ? '--' : `${(value * 100).toFixed(2)}%`;
  }
}
