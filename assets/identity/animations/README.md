# planarian motion prototypes

Both motions deform the original vector contours. The ring keeps its orientation,
the head stays nearly still, and the two eye cutouts remain part of the same shape.
There is no rotation or opacity flashing.

| State | Character | Cycle |
| --- | --- | --- |
| loading | More pronounced breathing and a slight tail flex; suitable for preparation or waiting. | 3.6 s |
| working | A contraction travels counterclockwise around the body, with a small tail response. | 2.4 s |

These are indeterminate activity indicators. Use progress text or a separate
progress bar when actual completion is known. Use a distinct status indication
for completion, failure, or a request for user input.

## Preview

Open `prototype.html` directly in a browser. It is self-contained and has no
network dependencies. Controls: play/pause, speed from 0.5× to 1.5×, background
theme, and reset. A reduced-motion preference pauses the prototype initially;
the viewer can explicitly choose play.

`planarian-motion-preview.gif` compares both states over 7.2 seconds: two loading
cycles and three working cycles. Individual GIFs are `loading-light.gif`,
`loading-dark.gif`, `working-light.gif`, and `working-dark.gif`, at 512 square.
GIFs are visual previews; the SVG and JavaScript versions provide reduced-motion
handling for integration.

## Animated SVG

Choose black for a light surface, white for a dark surface:

```html
<img src="/animations/loading-black.svg" width="96" height="96" alt="loading">
<img src="/animations/working-white.svg" width="96" height="96" alt="working">
```

The four animated SVGs are transparent and script-free. The path morph has 49
keyframes including the repeated end frame. An internal media query displays the
static master instead of the animated group when reduced motion is requested.
Use activity text alongside the symbol; do not announce each animation frame to
screen readers. The prototypes are clearest at 64 px and above. The supplied
static micro mark remains suitable for compact panels and favicons.

## Web or native integration

`planarian-motion.js` exports:

```js
import { motionPath, staticPath, durations } from './planarian-motion.js';

// elapsedSeconds is controlled by the integrating application's animation loop.
const phase = elapsedSeconds / durations.working;
pathElement.setAttribute('d', motionPath('working', phase));
```

Use `staticPath` when animation is disabled. `motionPath` accepts any cycle phase
and wraps it periodically; the original shape is centered in a 1024-square
viewBox. The interactive prototype shows pause and reduced-motion handling.

`keyframes.json` is a format-independent list of SVG path strings, offsets, and
durations for native renderers. Its format identifier is
`planarian-svg-path-keyframes-v1`; it is not a Lottie file. Interpolate matching
path coordinates between successive offsets, or render the supplied frames.

The editable deformation functions are in `source/build_motion.cjs`. They use
smooth periodic fields, with head movement damped and a localized tail flex.
The working wave changes body thickness rather than spinning the mark. Version
1.2 triples the radial breathing displacement and reverses the working cycle.
