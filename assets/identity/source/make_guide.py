#!/usr/bin/env python3
"""Build the portable visual guide and populate the Linux icon-theme layout."""
from pathlib import Path
import base64
import json
import shutil

ROOT = Path(__file__).resolve().parent.parent


def uri(name, mime):
    return 'data:' + mime + ';base64,' + base64.b64encode((ROOT / name).read_bytes()).decode()


def img(name, alt, cls='', width=None):
    mime = 'image/svg+xml' if name.endswith('.svg') else 'image/png'
    size = f' width="{width}" height="{width}"' if width else ''
    return f'<img src="{uri(name, mime)}" alt="{alt}" class="{cls}"{size}>'


def panel(title, name, alt, dark=False, cls=''):
    return f'<section class="sample {"dark" if dark else ""} {cls}"><h3>{title}</h3>{img(name, alt)}</section>'


small = ''.join(f'<div class="size-item">{img(f"web/favicon-{size}.png", f"{size} pixel favicon", width=size)}<span>{size} px</span></div>' for size in (16,24,32,48,64))
light_sizes = ''.join(f'<div class="size-item">{img(f"icons/light/planarian-{size}.png", f"{size} pixel light launcher", width=size)}<span>{size} px</span></div>' for size in (16,24,32,48,64))
cards = panel('01 / Primary mark', 'marks/planarian-mark-black.svg', 'Black planarian Return mark')
cards += panel('02 / Reversed mark', 'marks/planarian-mark-white.svg', 'White planarian Return mark', True)
cards += panel('03 / Horizontal wordmark', 'wordmarks/planarian-horizontal-light.svg', 'Black horizontal planarian wordmark', cls='wide-logo')
cards += panel('04 / Reversed wordmark', 'wordmarks/planarian-horizontal-dark.svg', 'White horizontal planarian wordmark', True, 'wide-logo')
cards += panel('05 / Dark launcher', 'icons/planarian-app-dark.svg', 'White mark on charcoal rounded launcher tile')
cards += panel('06 / Light launcher', 'icons/planarian-app-light.svg', 'Black mark on white rounded launcher tile')
cards += panel('07 / Circular avatar', 'social/planarian-avatar-dark.svg', 'White mark on charcoal circular avatar')
cards += panel('08 / Stacked wordmark', 'wordmarks/planarian-stacked-light.svg', 'Black vertically stacked planarian wordmark', cls='stacked')
html = f'''<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>planarian identity kit</title>
<style>
:root{{--paper:#f5f4ef;--ink:#151719;--muted:#6b7376;--line:#dedfd8}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--paper);color:var(--ink);font:16px/1.55 Arial,Helvetica,sans-serif}}
main{{max-width:1200px;margin:auto;padding:64px 36px 80px}}header{{border-bottom:1px solid var(--line);padding-bottom:34px;margin-bottom:40px}}
.eyebrow{{font-size:12px;letter-spacing:.2em;color:var(--muted)}}h1{{font-weight:500;font-size:clamp(42px,6vw,72px);letter-spacing:-.045em;line-height:1.1;margin:14px 0 18px}}
h2{{font-weight:500;font-size:30px;letter-spacing:-.025em;margin:58px 0 22px}}p{{max-width:780px;color:#515b60}}
.grid{{display:grid;grid-template-columns:1fr 1fr;gap:16px}}.sample{{min-height:300px;border:1px solid var(--line);border-radius:16px;background:#fff;display:flex;align-items:center;justify-content:center;position:relative;padding:62px 40px 36px}}
.sample.dark{{background:#151719;border-color:#151719}}h3{{position:absolute;left:24px;top:14px;font-size:11px;font-weight:400;letter-spacing:.10em;color:#727a7d}}
.sample.dark h3{{color:#adb3b5}}.sample img{{width:180px;max-width:100%;height:auto}}.sample.wide-logo img{{width:400px}}.sample.stacked img{{width:160px}}
.sizes{{display:flex;gap:36px;align-items:end;flex-wrap:wrap;padding:28px;background:#fff;border:1px solid var(--line);border-radius:16px}}.size-item{{display:flex;align-items:center;flex-direction:column;gap:14px;min-width:64px}}.size-item img{{max-width:none;display:block}}.size-item span{{font-size:12px;color:var(--muted)}}
.swatches{{display:flex;gap:16px;flex-wrap:wrap}}.swatch{{width:180px;height:110px;border-radius:14px;border:1px solid var(--line);padding:16px;display:flex;align-items:end;font-size:13px}}
.full{{width:100%;height:auto;display:block;border-radius:16px;border:1px solid var(--line)}}table{{border-collapse:collapse;width:100%;background:#fff;border-radius:12px;overflow:hidden}}th,td{{padding:14px 18px;text-align:left;border-bottom:1px solid #ecece6;vertical-align:top}}th{{font-size:12px;letter-spacing:.07em;text-transform:uppercase;font-weight:500;color:var(--muted)}}code{{font-size:13px;overflow-wrap:anywhere}}a{{color:inherit;text-underline-offset:.2em}}footer{{margin-top:64px;border-top:1px solid var(--line);padding-top:22px;color:var(--muted);font-size:13px}}
@media(max-width:650px){{main{{padding:36px 18px}}.grid{{grid-template-columns:1fr}}.sample{{min-height:260px}}td,th{{padding:11px}}}}
@media print{{body{{background:white}}main{{padding:12px;max-width:none}}.sample{{break-inside:avoid}}h2{{break-after:avoid}}}}
</style>
<main><header><div class="eyebrow">planarian / identity kit 1.2</div><h1>planarian.<br>The Return identity.</h1><p>The chosen Return symbol, prepared for software interfaces, launcher tiles, documentation, profiles, social cards, and boot artwork. One vector master supplies every reusable asset.</p></header>
<div class="grid">{cards}</div>
<h2>Small sizes</h2><p>Actual pixel sizes. The 16–32 px versions enlarge the eye cutouts; the body remains consistent. Use the micro symbol for compact panels and favicons, and the standard symbol for larger branding.</p><div class="sizes">{small}</div><div class="sizes" style="margin-top:16px">{light_sizes}</div>
<h2>Motion prototypes</h2><p><strong>Loading:</strong> more pronounced breathing and a small tail flex. <strong>Working:</strong> a counterclockwise contraction around the body. The head stays almost still. <a href="../animations/prototype.html">Open the interactive motion prototype</a> to pause, change speed, and compare light and dark backgrounds. Animated SVGs include a static reduced-motion treatment.</p>
<h2>Color and spacing</h2><div class="swatches"><div class="swatch" style="background:#000;color:#fff">Black / #000000</div><div class="swatch" style="background:#fff">White / #FFFFFF</div><div class="swatch" style="background:#151719;color:#fff">Charcoal / #151719</div></div><p>Keep the head at the upper right. Scale uniformly, retain the transparent cutouts, and preserve the supplied padding. Leave about one eighth of the mark height clear around the artwork. Use the designed motion for loading and working states; put health status and action indicators beside the mark.</p>
<h2>Software applications</h2>{img('previews/software-applications.svg', 'The planarian mark in a documentation header, terminal titlebar, launcher tiles, and panel symbols', 'full')}<p>The interface is illustrative. The actual vector mark and icon assets are used throughout this preview.</p>
<h2>Boot and social</h2>{img('previews/boot-dark.svg', 'Dark planarian boot artwork with the white mark and outlined wordmark', 'full')}<div style="height:16px"></div>{img('social/planarian-card-light.svg', 'planarian repository or social card on a light surface', 'full')}
<h2>Asset map</h2><table><tr><th>Folder</th><th>Contents</th></tr><tr><td><code>marks/</code></td><td>Black, white, and currentColor SVGs; standard and micro variants; transparent PNGs.</td></tr><tr><td><code>wordmarks/</code></td><td>Horizontal and stacked lockups for light and dark surfaces. Lettering is outlined.</td></tr><tr><td><code>icons/</code></td><td>Launcher SVGs and PNGs from 16 to 1024 px; a symbolic panel icon.</td></tr><tr><td><code>web/</code></td><td>Adaptive SVG favicon, multi-size ICO, touch icon, maskable app icons, CSS helper, SVG sprite, and starter manifest.</td></tr><tr><td><code>social/</code></td><td>Round avatars and 1280 × 640 cards in light and dark versions.</td></tr><tr><td><code>previews/</code></td><td>Identity board, exact software-context layout, and 1920 × 1080 boot artwork.</td></tr><tr><td><code>integration/linux/</code></td><td>hicolor theme layout and a desktop-entry template.</td></tr><tr><td><code>source/</code></td><td>Raster master, trace data, generation prompts, and regeneration scripts.</td></tr></table>
<footer>Wordmarks: Nimbus Sans Regular, converted to vector paths. Open README.md for integration guidance and naming conventions.</footer></main></html>'''
(ROOT / 'docs/guide.html').write_text(html)
integration = ROOT / 'integration/linux/hicolor'
for size in [16,20,24,32,48,64,96,128,192,256,512,1024]:
    target = integration / f'{size}x{size}/apps/planarian.png'
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / f'icons/dark/planarian-{size}.png', target)
for folder, source, name in [('scalable/apps','icons/planarian-app-dark.svg','planarian.svg'),('symbolic/apps','icons/symbolic/planarian-symbolic.svg','planarian-symbolic.svg')]:
    target = integration / folder / name
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / source, target)
print(json.dumps({'guide_bytes': (ROOT/'docs/guide.html').stat().st_size, 'linux_assets': len(list(integration.rglob('*.*')))}, indent=2))
