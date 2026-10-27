#!/usr/bin/env python3
"""Trace the approved raster silhouette to vector paths and build the identity assets.

Raster reading is used only for vectorization. All kit layouts and variants are
native SVG; PNG/ICO files are format exports from these SVG masters.
"""
from __future__ import annotations

import ctypes as C
import ctypes.util
import json
from pathlib import Path
from xml.sax.saxutils import escape

from PIL import Image
from fontTools.ttLib import TTFont
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.pens.boundsPen import BoundsPen

ROOT = Path(__file__).resolve().parent.parent
FONT = Path('/usr/share/fonts/opentype/urw-base35/NimbusSans-Regular.otf')
for folder in ('marks', 'wordmarks', 'icons/dark', 'icons/light', 'icons/symbolic', 'web', 'social', 'previews', 'docs'):
    (ROOT / folder).mkdir(parents=True, exist_ok=True)


class Point(C.Structure):
    _fields_ = [('x', C.c_double), ('y', C.c_double)]


class Curve(C.Structure):
    _fields_ = [('n', C.c_int), ('tag', C.POINTER(C.c_int)), ('c', C.POINTER(Point * 3))]


class TracePath(C.Structure):
    pass


TracePath._fields_ = [('area', C.c_int), ('sign', C.c_int), ('curve', Curve),
                     ('next', C.POINTER(TracePath)), ('childlist', C.POINTER(TracePath)),
                     ('sibling', C.POINTER(TracePath)), ('priv', C.c_void_p)]


class State(C.Structure):
    _fields_ = [('status', C.c_int), ('plist', C.POINTER(TracePath)), ('priv', C.c_void_p)]


class Bitmap(C.Structure):
    _fields_ = [('w', C.c_int), ('h', C.c_int), ('dy', C.c_int), ('map', C.POINTER(C.c_ulong))]


def trace():
    image = Image.open(ROOT / 'source/mark-raster.png').convert('RGBA')
    width, height = image.size
    pixels = list(image.get_flattened_data() if hasattr(image, 'get_flattened_data') else image.getdata())
    word_bits = C.sizeof(C.c_ulong) * 8
    stride = (width + word_bits - 1) // word_bits
    words = (C.c_ulong * (stride * height))()
    xs, ys = [], []
    for index, (r, g, b, a) in enumerate(pixels):
        if a >= 128 and max(r, g, b) < 128:
            y, x = divmod(index, width)
            words[y * stride + x // word_bits] |= 1 << (word_bits - 1 - x % word_bits)
            xs.append(x)
            ys.append(y)
    bounds = (min(xs), min(ys), max(xs) + 1, max(ys) + 1)
    lib = C.CDLL(ctypes.util.find_library('potrace'))
    lib.potrace_param_default.restype = C.c_void_p
    lib.potrace_trace.argtypes = [C.c_void_p, C.POINTER(Bitmap)]
    lib.potrace_trace.restype = C.POINTER(State)
    lib.potrace_state_free.argtypes = [C.POINTER(State)]
    lib.potrace_param_free.argtypes = [C.c_void_p]
    params = lib.potrace_param_default()
    bitmap = Bitmap(width, height, stride, words)
    state = lib.potrace_trace(params, C.byref(bitmap))
    assert state and state.contents.status == 0, 'Vector trace did not complete'
    curves = []
    item = state.contents.plist
    while item:
        p = item.contents
        if p.area >= 20:
            curve = p.curve
            segments = [(curve.tag[i], [(curve.c[i][j].x, curve.c[i][j].y) for j in range(3)]) for i in range(curve.n)]
            curves.append({'area': p.area, 'sign': p.sign, 'segments': segments})
        item = p.next
    lib.potrace_state_free(state)
    lib.potrace_param_free(params)
    assert len(curves) == 3, f'Expected body and two eye holes, found {len(curves)} contours'
    curves.sort(key=lambda c: c['area'], reverse=True)
    scale = 800 / max(bounds[2] - bounds[0], bounds[3] - bounds[1])
    offset_x = (1024 - (bounds[2] - bounds[0]) * scale) / 2 - bounds[0] * scale
    offset_y = (1024 - (bounds[3] - bounds[1]) * scale) / 2 - bounds[1] * scale

    def commands(curve, eye_scale=1.0):
        raw = [point for _, points in curve['segments'] for point in points]
        cx = (min(x for x, y in raw) + max(x for x, y in raw)) / 2
        cy = (min(y for x, y in raw) + max(y for x, y in raw)) / 2

        def fmt(point):
            x, y = point
            x, y = cx + (x - cx) * eye_scale, cy + (y - cy) * eye_scale
            return f'{x * scale + offset_x:.3f},{y * scale + offset_y:.3f}'

        out = ['M' + fmt(curve['segments'][-1][1][2])]
        for tag, points in curve['segments']:
            if tag == 1:
                out.append('C' + ' '.join(fmt(p) for p in points))
            else:
                out.append('L' + fmt(points[1]) + ' ' + fmt(points[2]))
        out.append('Z')
        return ' '.join(out)

    standard = ' '.join(commands(curve) for curve in curves)
    micro = ' '.join(commands(curve, 1.65 if i else 1.0) for i, curve in enumerate(curves))
    (ROOT / 'source/trace-data.json').write_text(json.dumps({'bounds': bounds, 'contours': curves}, indent=2))
    return standard, micro


PATH, MICRO_PATH = trace()


def glyph(fill='#000000', micro=False, transform=None):
    path = f'<path d="{MICRO_PATH if micro else PATH}" fill="{fill}" fill-rule="evenodd"/>'
    return f'<g transform="{transform}">{path}</g>' if transform else path


def svg(body, width=1024, height=1024, title='planarian', extra=''):
    return f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-label="{escape(title)}" {extra}><title>{escape(title)}</title>{body}</svg>\n'


def write(name, content):
    (ROOT / name).write_text(content)


def text(x, y, value, size=24, color='#111111', weight='400', family='Arial, Helvetica, sans-serif', extra=''):
    return f'<text x="{x}" y="{y}" fill="{color}" font-family="{family}" font-size="{size}" font-weight="{weight}" {extra}>{escape(value)}</text>'


font = TTFont(FONT)
glyph_set = font.getGlyphSet()
cmap = font.getBestCmap()
units = font['head'].unitsPerEm


def outlined_word(value='planarian', size=228, x=360, baseline=None, fill='#000000'):
    pen = SVGPathPen(glyph_set)
    bounds = BoundsPen(glyph_set)
    position = 0
    for letter in value:
        name = cmap[ord(letter)]
        glyph_set[name].draw(TransformPen(pen, (1, 0, 0, 1, position, 0)))
        glyph_set[name].draw(TransformPen(bounds, (1, 0, 0, 1, position, 0)))
        position += font['hmtx'][name][0]
    scale = size / units
    if baseline is None:
        baseline = 256 + (bounds.bounds[1] + bounds.bounds[3]) * scale / 2
    return f'<path d="{pen.getCommands()}" fill="{fill}" transform="translate({x},{baseline}) scale({scale}, {-scale})"/>', position * scale


for name, color in [('black', '#000000'), ('white', '#ffffff'), ('currentcolor', 'currentColor')]:
    write(f'marks/planarian-mark-{name}.svg', svg(glyph(color)))
    write(f'marks/planarian-mark-micro-{name}.svg', svg(glyph(color, True)))

write('web/planarian-symbols.svg', f'<svg xmlns="http://www.w3.org/2000/svg"><symbol id="planarian" viewBox="0 0 1024 1024">{glyph("currentColor")}</symbol><symbol id="planarian-micro" viewBox="0 0 1024 1024">{glyph("currentColor", True)}</symbol></svg>\n')
write('web/planarian-mask.svg', svg(glyph()))
write('icons/symbolic/planarian-symbolic.svg', svg(glyph('currentColor', True)))

for name, ink, background in [('dark', '#ffffff', '#151719'), ('light', '#000000', '#ffffff')]:
    tile = f'<rect x="0" y="0" width="1024" height="1024" rx="208" fill="{background}"/>'
    mark = glyph(ink, transform='translate(51.2 51.2) scale(.9)')
    write(f'icons/planarian-app-{name}.svg', svg(tile + mark, title=f'planarian {name} app icon'))
    write(f'icons/planarian-app-{name}-micro.svg', svg(tile + glyph(ink, True, 'translate(30.72 30.72) scale(.94)'), title=f'planarian {name} small app icon'))
    maskable = f'<rect width="1024" height="1024" fill="{background}"/>' + mark
    write(f'web/planarian-maskable-{name}.svg', svg(maskable))
    avatar = f'<circle cx="512" cy="512" r="512" fill="{background}"/>' + glyph(ink, transform='translate(61.44 61.44) scale(.88)')
    write(f'social/planarian-avatar-{name}.svg', svg(avatar))
    word, word_width = outlined_word(fill=ink)
    wordmark_width = int(word_width + 440)
    write(f'wordmarks/planarian-horizontal-{name}.svg', svg(glyph(ink, transform='translate(48 112.64) scale(.28)') + word, wordmark_width, 512))
    stacked_word, stacked_width = outlined_word(size=200, x=0, baseline=1140, fill=ink)
    stacked_word = f'<g transform="translate({(1024 - stacked_width) / 2} 0)">{stacked_word}</g>'
    write(f'wordmarks/planarian-stacked-{name}.svg', svg(glyph(ink) + stacked_word, 1024, 1248))
    # A social/repository card with no invented marketing copy.
    card = f'<rect width="1280" height="640" fill="{background}"/>'
    card += glyph(ink, transform='translate(850 88) scale(.43)')
    word, _ = outlined_word(size=112, x=88, baseline=350, fill=ink)
    card += word
    card += text(92, 406, 'Self-healing systems', 27, ink)
    write(f'social/planarian-card-{name}.svg', svg(card, 1280, 640))
    # Exact reusable boot artwork; the mark is centered and unmodified.
    boot = f'<rect width="1920" height="1080" fill="{background}"/>'
    boot += glyph(ink, transform='translate(780 290) scale(.3515625)')
    word, word_width = outlined_word(size=74, x=0, baseline=746, fill=ink)
    boot += f'<g transform="translate({(1920-word_width)/2} 0)">{word}</g>'
    write(f'previews/boot-{name}.svg', svg(boot, 1920, 1080))

adaptive = '<style>:root{--ink:#000;--paper:#fff}@media(prefers-color-scheme:dark){:root{--ink:#fff;--paper:#151719}}</style>'
adaptive += '<rect width="1024" height="1024" rx="208" fill="var(--paper)"/>' + glyph('var(--ink)', True)
write('web/favicon.svg', svg(adaptive))

# A precise, reusable software-context preview; no generated UI copy is required.
ui = '<rect width="1600" height="1000" rx="28" fill="#f4f3ef"/>'
ui += '<rect x="30" y="30" width="1540" height="940" rx="20" fill="#ffffff" stroke="#ddddda"/>'
ui += '<path d="M30 125H1570" stroke="#e6e6e3"/>'
ui += glyph(transform='translate(61 43) scale(.0625)') + text(145, 91, 'planarian', 30, weight='600')
ui += text(1195, 88, 'Docs', 22) + text(1310, 88, 'Reference', 22, '#5e6469')
ui += text(96, 223, 'Getting started', 62, weight='600')
ui += text(99, 274, 'A self-healing layer for declaratively configured computers.', 25, '#596167')
ui += '<rect x="98" y="328" width="665" height="548" rx="14" fill="#151719"/>'
ui += glyph('#ffffff', transform='translate(119 347) scale(.035)')
ui += text(169, 375, 'planarian', 20, '#f6f6f4')
ui += '<path d="M98 400H763" stroke="#323638"/>'
ui += text(130, 456, '$ planarian status', 25, '#ffffff', family='DejaVu Sans Mono, monospace')
ui += text(130, 509, 'All systems healthy', 23, '#e2e4df', family='DejaVu Sans Mono, monospace')
ui += text(130, 584, 'Services     healthy', 21, '#a9afb2', family='DejaVu Sans Mono, monospace')
ui += text(130, 627, 'Incidents    none open', 21, '#a9afb2', family='DejaVu Sans Mono, monospace')
ui += text(130, 670, 'Recovery     available', 21, '#a9afb2', family='DejaVu Sans Mono, monospace')
ui += '<rect x="813" y="328" width="690" height="548" rx="14" fill="#fafaf7" stroke="#e8e8e2"/>'
ui += text(855, 383, 'Applications', 23, '#6b7377')
for x, name, color, bg in [(860, 'Dark', '#ffffff', '#151719'), (1106, 'Light', '#000000', '#ffffff')]:
    ui += f'<rect x="{x}" y="424" width="168" height="168" rx="35" fill="{bg}" stroke="#deded8"/>'
    ui += glyph(color, transform=f'translate({x+8.4} 432.4) scale(.14765625)')
    ui += text(x + 84, 632, name, 20, '#626a6e', extra='text-anchor="middle"')
ui += text(855, 718, 'Panel and toolbar', 21, '#6b7377')
ui += '<rect x="855" y="746" width="597" height="70" rx="12" fill="#eaeae5"/>'
for x in (880, 966, 1062):
    ui += glyph(transform=f'translate({x} 761) scale(.0390625)')
ui += text(1143, 788, 'planarian', 23)
ui += text(99, 933, 'Illustrative interface application', 18, '#7a8083')
write('previews/software-applications.svg', svg(ui, 1600, 1000))

# Usage specification for render/export tooling.
manifest = {
    'name': 'planarian Return identity kit',
    'version': '1.2',
    'canvas': 1024,
    'standard_mark_height': 800,
    'micro_eye_scale': 1.65,
    'monochrome': {'black': '#000000', 'white': '#ffffff', 'surface_dark': '#151719', 'surface_light': '#ffffff'},
    'font': 'Nimbus Sans Regular; wordmarks are outlined, with no font dependency',
    'icon_sizes': [16, 20, 24, 32, 48, 64, 96, 128, 192, 256, 512, 1024],
    'mark_contours': 3,
}
write('source/manifest.json', json.dumps(manifest, indent=2) + '\n')
print(json.dumps({'contours': 3, 'svg_files': len(list(ROOT.rglob('*.svg'))), 'root': str(ROOT)}, indent=2))
