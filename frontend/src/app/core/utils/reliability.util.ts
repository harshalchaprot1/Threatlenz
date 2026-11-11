import { ModelDiagnosticsResponse, ThreatProfileSummary } from '../models';

/**
 * Shared, authoritative Model Reliability Tier resolution helper.
 *
 * Implements strict Section 5 validation gating logic across both Threat Explorer
 * and Profile Inspection screens to ensure 100% presentation parity:
 * - Benign reference baseline traffic -> strictly 'BASELINE' (displays 'Baseline (N/A)')
 * - Evaluated attack categories -> verified official reliability tier from diagnostics report
 * - Missing diagnostics or un-evaluated attack categories -> 'UNMATCHED' (displays 'Not Evaluated')
 * - Operational live ML prediction is disabled by governance policy; this evaluates
 *   academic benchmark validation metrics only.
 */
export function resolveReliabilityTier(
  profile: ThreatProfileSummary,
  diagnostics: ModelDiagnosticsResponse | null
): string {
  // 1. If backend explicitly provided a verified model_reliability on the record, prioritize it
  if (profile.model_reliability) {
    return profile.model_reliability;
  }

  // 2. Benign reference baseline or non-attack profile is strictly Negative Baseline
  if (!profile.is_attack || profile.canonical_label === 'Benign') {
    return 'BASELINE';
  }

  // 3. If diagnostics API call failed, timed out, or is unavailable for an attack profile
  if (!diagnostics) {
    return 'UNAVAILABLE';
  }

  // 4. Exact-match canonical_label against authoritative category_evaluations class_name
  if (diagnostics.category_evaluations && diagnostics.category_evaluations.length > 0) {
    const match = diagnostics.category_evaluations.find(
      (e) => e.class_name === profile.canonical_label
    );
    if (match?.official_reliability_tier) {
      return match.official_reliability_tier;
    }
  }

  // 5. Successful diagnostics response but no evaluation record exists for this attack category
  return 'UNMATCHED';
}
