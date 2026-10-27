# planarian identity kit

The selected **C / Return** symbol, prepared as a reusable monochrome identity.
Version 1.2 uses lowercase **planarian** lettering throughout and adds organic
loading and working motion prototypes. Open `docs/guide.html` for the visual guide
and `previews/identity-board.png` for the identity overview.
`previews/software-applications.png` shows the actual vector assets in software contexts.

## Motion prototypes

Open `animations/prototype.html` for a self-contained comparison with play/pause,
speed, and light/dark background controls. It starts paused when reduced motion
is requested. `animations/planarian-motion-preview.gif` is the looping comparison.

- **loading:** more pronounced breathing with a small tail flex; 3.6-second cycle.
- **working:** a counterclockwise muscular contraction around the body; 2.4-second cycle.
- Animated SVGs: `loading-black.svg`, `loading-white.svg`, `working-black.svg`,
  and `working-white.svg`. They retain transparent cutouts and show a static mark
  under the reduced-motion preference.
- GIF previews have light and dark backgrounds. `animations/planarian-motion.js`
  and `animations/keyframes.json` supply editable motion for web and native use.

See `animations/README.md` for timings, controls, and integration examples.

## Start here

| Use | Asset |
| --- | --- |
| General mark on light surfaces | `marks/planarian-mark-black.svg` |
| General mark on dark surfaces | `marks/planarian-mark-white.svg` |
| Inline SVG or CSS-controlled color | `marks/planarian-mark-currentcolor.svg` |
| Small panel/toolbar symbol, 16–32 px | `marks/planarian-mark-micro-currentcolor.svg` |
| Horizontal identity on light surfaces | `wordmarks/planarian-horizontal-light.svg` |
| Horizontal identity on dark surfaces | `wordmarks/planarian-horizontal-dark.svg` |
| Stacked wordmarks | `wordmarks/planarian-stacked-light.svg`, `-dark.svg` |
| App launcher | `icons/planarian-app-dark.svg`, `-light.svg` |
| Circular profile/avatar | `social/planarian-avatar-dark.svg`, `-light.svg` |
| Repository or social card | `social/planarian-card-dark.png`, `-light.png` (1280 × 640) |
| Boot/login artwork | `previews/boot-dark.svg`, `-light.svg` (1920 × 1080) |

The wordmark names describe their **background**: `light` is black artwork for a
light surface; `dark` is white artwork for a dark surface. The standalone marks
use explicit `black` and `white` names.

## Formats and sizes

- SVG masters are vector paths with real transparent eyes and center cutouts.
  They contain no embedded bitmap. Wordmark lettering is outlined and needs no
  installed font.
- Transparent standalone mark PNGs: 128, 256, 512, and 1024 px, black and white.
- Launcher PNGs: 16, 20, 24, 32, 48, 64, 96, 128, 192, 256, 512, and 1024 px,
  for dark and light tiles. The 16–32 px files use the micro variant.
- `web/favicon.svg` adapts to the preferred light/dark color scheme.
  `web/favicon.ico` contains 16, 24, 32, 48, and 64 px frames; its fixed dark tile
  keeps the white symbol visible on either browser surface.
- Web app icons: opaque maskable PNGs at 192 and 512 px. The square background
  gives platform masks room; the symbol stays inside the central safe area.
- `web/apple-touch-icon.png`: 180 px with an opaque background.

## Usage

The master canvas is 1024 square, with the symbol occupying 800 px in its largest
dimension. Preserve the supplied padding. Around the artwork, keep at least
one eighth of the visible mark height clear of other content when possible.

Use the standard mark at 48 px and above; use the micro mark at 16–32 px. The micro
variant has larger eye cutouts while preserving the body. For launcher tiles,
the small version also gives the symbol slightly more room within the tile.
At very small sizes the silhouette carries recognition; the eyes are a secondary
detail. Both versions are shown in the guide at their actual raster sizes.

Keep the head at the upper right. Scale uniformly. Use the supplied black or white
fill, a high-contrast surface, and the original transparent cutouts. Keep the
identity mark consistent; use the designed loading/working motion for activity,
and separate icons or badges for health status and actions.

The visual system is monochrome: black `#000000`, white `#FFFFFF`, and charcoal
surface `#151719`. Wordmarks use outlined Nimbus Sans Regular lettering. UI
examples use ordinary sans-serif and monospaced interface text.

## Web and Linux integration

- `web/head-snippet.html`: favicon and web app icon markup; adapt file paths.
- `web/planarian.css`: an inline-color CSS mask helper.
- `web/planarian-symbols.svg`: standard and micro SVG symbols.
- `web/site.webmanifest`: starter icon manifest; adapt name, start URL, and colors
  to the integrating app.
- `integration/linux/hicolor/`: ready-to-copy launcher and symbolic theme assets.
- `integration/linux/planarian.desktop`: desktop-entry template; adjust `Exec` to
  the built console binary.

The previews illustrate identity placement. They are design examples; interface
wording is not an implementation of the planarian console or CLI.

## Source and regeneration

`source/mark-raster.png` is the transparent master isolated from the selected
concept using the built-in image-generation tool. The production vectors were
traced from that silhouette with Potrace, and every reusable asset derives from
those same paths. `source/prompts.md` records the image-generation prompts.

`source/build_kit.py` rebuilds SVG assets using Pillow for input reading,
FontTools for outlined lettering, and the Potrace shared library. It uses the
system Nimbus Sans Regular font; set its `FONT` path for another environment.
`source/export_kit.cjs` exports PNG/ICO formats using Node, Sharp, and ImageMagick.
`source/make_guide.py` rebuilds the guide and Linux theme layout.
`source/build_motion.cjs` rebuilds the organic animations and the exact lowercase
identity overview. These tools are only needed for regeneration; the supplied
assets are ready to use.
