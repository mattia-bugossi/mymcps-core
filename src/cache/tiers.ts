// purpose: shared cache TTL tiers — one table, three freshness contracts.
//
// Daily: the "per-day summary" freshness for anything that re-scores once a day
// (Oura readiness_score, daily activity, sleep summary, Withings sleep/activity).
// 48h covers weekend gaps plus an auto-refresh the morning after.
//
// Weekly / monthly: longer horizons for aggregators and trend windows where the
// underlying value is less likely to be retroactively edited. 14d / 90d both
// exceed a single billing-month window so backfills stay covered.

export type CacheTier = 'daily' | 'weekly' | 'monthly';

export const TIER_TTL_SECONDS: Record<CacheTier, number> = {
  daily: 48 * 3600,
  weekly: 14 * 24 * 3600,
  monthly: 90 * 24 * 3600,
};
