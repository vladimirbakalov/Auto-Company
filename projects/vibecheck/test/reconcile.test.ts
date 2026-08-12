// fetchKnownStripeCustomerIds (the D1 wrapper in src/reconcile.ts) is not
// covered here for the same reason auth.ts's D1 wrappers aren't: no
// miniflare/D1 pool is wired into vitest in this codebase (see the STUB
// notes at the top of test/auth.test.ts's counterpart, src/auth.ts). Only
// the pure gap-detection function — the actual bug-signature logic — is
// unit-tested; fetchActiveStripeCustomerIds (the Stripe HTTP half) is
// covered in test/stripe.test.ts.

import { describe, it, expect } from 'vitest';
import { findReconciliationGap } from '../src/reconcile';

describe('findReconciliationGap', () => {
  it('returns an empty list when every Stripe customer id is known to D1', () => {
    const gap = findReconciliationGap(['cus_A', 'cus_B'], new Set(['cus_A', 'cus_B']));
    expect(gap).toEqual([]);
  });

  it('flags a Stripe customer id with no matching D1 row', () => {
    const gap = findReconciliationGap(['cus_A', 'cus_B'], new Set(['cus_A']));
    expect(gap).toEqual(['cus_B']);
  });

  it('flags multiple missing customer ids, preserving input order', () => {
    const gap = findReconciliationGap(['cus_A', 'cus_B', 'cus_C'], new Set(['cus_B']));
    expect(gap).toEqual(['cus_A', 'cus_C']);
  });

  it('returns an empty list when Stripe has no active/trialing subscriptions', () => {
    const gap = findReconciliationGap([], new Set(['cus_A']));
    expect(gap).toEqual([]);
  });

  it('flags every Stripe customer id when D1 knows about none', () => {
    const gap = findReconciliationGap(['cus_A', 'cus_B'], new Set());
    expect(gap).toEqual(['cus_A', 'cus_B']);
  });
});
