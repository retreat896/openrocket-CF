// All features are free. This compatibility module remains because existing pages share it.
export async function requirePlan() {
  return { access: { ok: true, full: true, kind: 'free' } };
}
