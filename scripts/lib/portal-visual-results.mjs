export function portalGeometryProbe() {
  const vw = document.documentElement.clientWidth;
  const issues = { pageOverflowX: document.documentElement.scrollWidth - vw, offscreen: [], smallTargets: [], clippedText: [], overlapAssessment: 'not_measured' };
  const label = (el) => `${el.tagName.toLowerCase()}${el.id ? `#${el.id}` : ''}${el.classList.length ? `.${[...el.classList].slice(0, 3).join('.')}` : ''} "${(el.getAttribute('aria-label') || el.textContent || '').trim().replace(/\s+/g, ' ').slice(0, 40)}"`;
  const inScroller = (el) => {
    for (let p = el.parentElement; p && p !== document.body; p = p.parentElement) {
      const s = getComputedStyle(p);
      if (/(auto|scroll|hidden|clip)/.test(s.overflowX) && p.scrollWidth > p.clientWidth + 1) return true;
    }
    return false;
  };
  const visible = (el) => {
    const r = el.getBoundingClientRect();
    const s = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none' && Number(s.opacity) > 0;
  };
  for (const el of document.querySelectorAll('body *')) {
    if (!visible(el)) continue;
    const r = el.getBoundingClientRect();
    if ((r.right > vw + 1 || r.left < -1) && !inScroller(el) && getComputedStyle(el).position !== 'fixed') {
      if (issues.offscreen.length < 15) issues.offscreen.push(`${label(el)} [${Math.round(r.left)}..${Math.round(r.right)}]`);
    }
  }
  const interactive = document.querySelectorAll('a[href], button, input:not([type=hidden]), select, textarea, [role=button], [role=tab], [role=link], [role=checkbox], [role=switch], summary');
  for (const el of interactive) {
    if (!visible(el)) continue;
    const r = el.getBoundingClientRect();
    const inline = el.tagName === 'A' && getComputedStyle(el).display === 'inline';
    if (!inline && (r.width < 44 || r.height < 44) && issues.smallTargets.length < 25) {
      issues.smallTargets.push(`${label(el)} ${Math.round(r.width)}x${Math.round(r.height)}`);
    }
  }
  for (const el of document.querySelectorAll('h1,h2,h3,h4,p,span,td,th,label,button,a,dt,dd,li,strong,code')) {
    if (!visible(el) || !el.childNodes.length || el.closest('.sr-only')) continue;
    const s = getComputedStyle(el);
    const r = el.getBoundingClientRect();
    const screenReaderOnly = s.position === 'absolute' && r.width <= 1 && r.height <= 1
      && s.clip.replace(/\s/g, '') === 'rect(0px,0px,0px,0px)';
    if (s.textOverflow === 'ellipsis' || screenReaderOnly) continue;
    if ((s.overflowX === 'hidden' || s.overflow === 'hidden' || s.overflowX === 'clip') && el.scrollWidth > el.clientWidth + 2 && issues.clippedText.length < 15) {
      issues.clippedText.push(`${label(el)} ${el.scrollWidth}>${el.clientWidth}`);
    }
  }
  return issues;
}

export function visualSweepFailures(report) {
  if (!report.length) return ['No route states were inspected.'];
  return report.flatMap((entry) => {
    const scope = `${entry.route}/${entry.theme}/${entry.viewport}`;
    const failures = [];
    if (entry.error) failures.push(`${scope}: ${entry.error}`);
    if ((entry.diagnostics ?? []).some((item) => item.classification !== 'audit_stylesheet_csp_refetch')) {
      failures.push(`${scope}: unexpected browser diagnostics`);
    }
    if ((entry.axe ?? []).length) failures.push(`${scope}: accessibility violations`);
    if (entry.axeStatus !== 'completed' && !(entry.viewport === 'tablet' && entry.axeStatus === 'not_run_tablet')) {
      failures.push(`${scope}: accessibility audit incomplete`);
    }
    const geometry = entry.geometry;
    if (!geometry) failures.push(`${scope}: geometry assessment missing`);
    else {
      if (geometry.pageOverflowX > 1 || geometry.offscreen?.length || geometry.clippedText?.length) {
        failures.push(`${scope}: overflow or clipped content`);
      }
      if (['mobile', 'tablet'].includes(entry.viewport) && geometry.smallTargets?.length) {
        failures.push(`${scope}: coarse-pointer targets smaller than 44px`);
      }
    }
    return failures;
  });
}
