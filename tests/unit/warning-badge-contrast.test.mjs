import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';

const CSS = readFileSync(
  new URL('../../apps/web/react/src/styles.css', import.meta.url),
  'utf8',
);

function themeRoot(selector) {
  const start = CSS.indexOf(selector);
  assert.notEqual(start, -1, `missing ${selector} theme root`);
  return CSS.slice(start, CSS.indexOf('\n}', start));
}

function themeToken(selector, name) {
  const match = themeRoot(selector).match(
    new RegExp(`--${name}:\\s*oklch\\(([\\d.]+)%\\s+([\\d.]+)\\s+([\\d.]+)`),
  );
  assert.ok(match, `missing ${selector} --${name} OKLCH token`);
  return { l: Number(match[1]) / 100, c: Number(match[2]), h: Number(match[3]) };
}

function darkToken(name) {
  return themeToken(':root {', name);
}

function lightToken(name) {
  return themeToken(':root[data-theme="light"]', name);
}

function toLab({ l, c, h }) {
  const radians = h * Math.PI / 180;
  return { l, a: c * Math.cos(radians), b: c * Math.sin(radians) };
}

function mixLab(first, second, secondWeight) {
  const a = toLab(first);
  const b = toLab(second);
  return {
    l: a.l * (1 - secondWeight) + b.l * secondWeight,
    a: a.a * (1 - secondWeight) + b.a * secondWeight,
    b: a.b * (1 - secondWeight) + b.b * secondWeight,
  };
}

function labToSrgb({ l: L, a, b }) {
  const l = (L + 0.3963377774 * a + 0.2158037573 * b) ** 3;
  const m = (L - 0.1055613458 * a - 0.0638541728 * b) ** 3;
  const s = (L - 0.0894841775 * a - 1.291485548 * b) ** 3;
  const linear = [
    4.0767416621 * l - 3.3077115913 * m + 0.2309699292 * s,
    -1.2684380046 * l + 2.6097574011 * m - 0.3413193965 * s,
    -0.0041960863 * l - 0.7034186147 * m + 1.707614701 * s,
  ];
  return linear.map((value) => {
    const clipped = Math.max(0, Math.min(1, value));
    return clipped <= 0.0031308
      ? 12.92 * clipped
      : 1.055 * clipped ** (1 / 2.4) - 0.055;
  });
}

function relativeLuminance(rgb) {
  const linear = rgb.map((value) => value <= 0.04045
    ? value / 12.92
    : ((value + 0.055) / 1.055) ** 2.4);
  return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2];
}

function contrast(first, second) {
  const [lighter, darker] = [relativeLuminance(first), relativeLuminance(second)].sort((a, b) => b - a);
  return (lighter + 0.05) / (darker + 0.05);
}

function composite(foreground, background, opacity) {
  return foreground.map(
    (channel, index) => channel * opacity + background[index] * (1 - opacity),
  );
}

function toHex(rgb) {
  return `#${rgb.map((channel) => Math.round(channel * 255).toString(16).padStart(2, '0')).join('')}`;
}

function darkDashboardBadgeContrast(tokenName, foregroundMix = 0) {
  const semantic = darkToken(tokenName);
  const foreground = darkToken('fg');
  const rowRule = CSS.match(
    /\.dashboard-link-list li\s*\{[\s\S]*?background: color-mix\(in oklab, var\(--fg\), transparent ([\d.]+)%\);[\s\S]*?\}/,
  );
  const fillMix = themeRoot(':root {').match(/--status-fill-mix:\s*([\d.]+)%/);
  assert.ok(rowRule, 'missing dashboard row foreground tint');
  assert.ok(fillMix, 'missing dark status fill mix');

  const semanticRgb = labToSrgb(toLab(semantic));
  const foregroundRgb = labToSrgb(toLab(foreground));
  const surfaceRgb = labToSrgb(toLab(darkToken('surface-2')));
  const rowBackground = composite(
    foregroundRgb,
    surfaceRgb,
    (100 - Number(rowRule[1])) / 100,
  );
  const badgeBackground = composite(
    semanticRgb,
    rowBackground,
    (100 - Number(fillMix[1])) / 100,
  );
  const text = labToSrgb(mixLab(semantic, foreground, foregroundMix));
  return { ratio: contrast(text, badgeBackground), text, background: badgeBackground };
}

function badgeContrast(tokenName, foregroundMix, parentTokenName) {
  const semantic = lightToken(tokenName);
  const foreground = lightToken('fg');
  const parent = lightToken(parentTokenName);
  const text = labToSrgb(mixLab(semantic, foreground, foregroundMix));
  const semanticRgb = labToSrgb(toLab(semantic));
  const parentRgb = labToSrgb(toLab(parent));
  // --status-fill-mix is 88% transparent, leaving a 12% semantic tint.
  const background = semanticRgb.map((channel, index) => channel * 0.12 + parentRgb[index] * 0.88);
  return contrast(text, background);
}

describe('default-dark dashboard semantic contrast', () => {
  it('keeps the small danger badge at or above WCAG AA on its composite row surface', () => {
    const override = CSS.match(
      /:root:not\(\[data-theme="light"\]\) \.dashboard-link-meta > \.badge-danger\.badge\.badge-sans\s*\{\s*color: color-mix\(in oklab, var\(--danger\), var\(--fg\) ([\d.]+)%\);/m,
    );
    assert.ok(override, 'missing scoped default-dark dashboard danger badge override');
    const result = darkDashboardBadgeContrast('danger', Number(override[1]) / 100);
    assert.ok(
      result.ratio >= 4.5,
      `dark dashboard danger badge was ${result.ratio.toFixed(2)}:1 (${toHex(result.text)} on ${toHex(result.background)})`,
    );
  });

  it('keeps warning and success badges at or above WCAG AA on the same composite surface', () => {
    for (const tokenName of ['warn', 'success']) {
      const result = darkDashboardBadgeContrast(tokenName);
      assert.ok(
        result.ratio >= 4.5,
        `dark dashboard ${tokenName} badge was ${result.ratio.toFixed(2)}:1 (${toHex(result.text)} on ${toHex(result.background)})`,
      );
    }
  });
});

describe('light-theme semantic contrast', () => {
  it('keeps warning badges at or above WCAG AA on light surfaces', () => {
    const override = CSS.match(/:root\[data-theme="light"\] \.badge-warn\s*\{\s*color: color-mix\(in oklab, var\(--warn\), var\(--fg\) ([\d.]+)%\);/m);
    assert.ok(override, 'missing scoped light-theme warning badge override');
    const mix = Number(override[1]) / 100;
    for (const parent of ['surface', 'surface-raised']) {
      const ratio = badgeContrast('warn', mix, parent);
      assert.ok(ratio >= 4.5, `light warning badge on ${parent} was ${ratio.toFixed(2)}:1`);
    }
  });

  it('keeps danger badges at or above WCAG AA on light surfaces', () => {
    const override = CSS.match(/:root\[data-theme="light"\] \.badge-danger\s*\{\s*color: color-mix\(in oklab, var\(--danger\), var\(--fg\) ([\d.]+)%\);/m);
    assert.ok(override, 'missing scoped light-theme danger badge override');
    const mix = Number(override[1]) / 100;
    for (const parent of ['surface', 'surface-raised']) {
      const ratio = badgeContrast('danger', mix, parent);
      assert.ok(ratio >= 4.5, `light danger badge on ${parent} was ${ratio.toFixed(2)}:1`);
    }
  });

  it('keeps raw warning-token text at or above WCAG AA on light surfaces', () => {
    const warning = labToSrgb(toLab(lightToken('warn')));
    for (const parent of ['surface', 'surface-raised']) {
      const ratio = contrast(warning, labToSrgb(toLab(lightToken(parent))));
      assert.ok(ratio >= 4.5, `raw light warning text on ${parent} was ${ratio.toFixed(2)}:1`);
    }
  });

  it('keeps warning and danger heatmap text at or above WCAG AA on computed tinted surfaces', () => {
    for (const kind of ['warn', 'danger']) {
      const cellRule = CSS.match(new RegExp(
        `\\.heatmap-${kind}\\s*\\{[\\s\\S]*?background: color-mix\\(in oklab, var\\(--${kind}\\), transparent ([\\d.]+)%\\);[\\s\\S]*?\\}`,
      ));
      const lightOverride = CSS.match(new RegExp(
        `:root\\[data-theme="light"\\] \\.heatmap-${kind}\\s*\\{\\s*color: color-mix\\(in oklab, var\\(--${kind}\\), var\\(--fg\\) ([\\d.]+)%\\);`,
      ));
      assert.ok(cellRule, `missing ${kind} heatmap tint`);
      assert.ok(lightOverride, `missing light ${kind} heatmap foreground override`);

      const tintWeight = (100 - Number(cellRule[1])) / 100;
      const foregroundMix = Number(lightOverride[1]) / 100;
      const semantic = lightToken(kind);
      const semanticRgb = labToSrgb(toLab(semantic));
      const text = labToSrgb(mixLab(semantic, lightToken('fg'), foregroundMix));

      for (const parent of ['surface', 'surface-raised']) {
        const parentRgb = labToSrgb(toLab(lightToken(parent)));
        const tintedSurface = semanticRgb.map(
          (channel, index) => channel * tintWeight + parentRgb[index] * (1 - tintWeight),
        );
        const ratio = contrast(text, tintedSurface);
        assert.ok(ratio >= 4.5, `light heatmap ${kind} on ${parent} was ${ratio.toFixed(2)}:1`);
      }
    }
  });
});
