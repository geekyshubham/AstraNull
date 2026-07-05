export function getRouteEntityId(fallback = '') {
  const hash = window.location.hash.replace(/^#/, '');
  const queryInHash = hash.includes('?') ? hash.slice(hash.indexOf('?') + 1) : '';
  const params = new URLSearchParams(queryInHash || window.location.search);
  return params.get('id') ?? params.get('entity_id') ?? fallback;
}

export function buildDetailHref(route: string, id: string) {
  const encoded = encodeURIComponent(id);
  return `${window.location.pathname}${window.location.search}#${route}?id=${encoded}`;
}