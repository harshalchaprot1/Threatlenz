/**
 * Health check models corresponding to FastAPI backend schemas.
 */

export interface DatabaseHealth {
  status: 'connected' | 'disconnected' | string;
  dialect: string;
}

export interface HealthResponse {
  status: 'healthy' | 'degraded' | string;
  database: DatabaseHealth;
  app_name: string;
  version: string;
  timestamp: string;
}

export interface ServiceMetadata {
  app_name: string;
  version: string;
  environment: string;
  docs_url: string;
  openapi_url: string;
}
