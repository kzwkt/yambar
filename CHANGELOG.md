# Changelog

* [Unreleased](#unreleased)
* [1.7.0](#1-7-0)
* [1.6.2](#1-6-2)
* [1.6.1](#1-6-1)
* [1.6.0](#1-6-0)
* [1.5.0](#1-5-0)


## Unreleased
### Added

* ramp: can now have custom min and max values
  (https://codeberg.org/dnkl/yambar/issues/103).
* border: new decoration.
* i3/sway: new boolean tag: `empty`
  (https://codeberg.org/dnkl/yambar/issues/139).
* mem: a module handling system memory monitoring
* cpu: a module offering cpu usage monitoring
* removables: support for audio CDs
  (https://codeberg.org/dnkl/yambar/issues/146).
* removables: new boolean tag: `audio`.


### Changed

* fcft >= 3.0 is now required.
* Made `libmpdclient` an optional dependency
* battery: unknown battery states are now mapped to ‘unknown’, instead
  of ‘discharging’.
* Wayland: the bar no longer exits when the monitor is
  disabled/unplugged (https://codeberg.org/dnkl/yambar/issues/106).


### Deprecated
### Removed
### Fixed

* `left-margin` and `right-margin` from being rejected as invalid
  options.
* Crash when `udev_monitor_receive_device()` returned `NULL`. This
  affected the “backlight”, “battery” and “removables” modules
  (https://codeberg.org/dnkl/yambar/issues/109).
* foreign-toplevel: update bar when a top-level is closed.
* Bar not being mapped on an output before at least one module has
  “refreshed” it (https://codeberg.org/dnkl/yambar/issues/116).
* network: failure to retrieve wireless attributes (SSID, RX/TX
  bitrate, signal strength etc).
* Integer options that were supposed to be >= 0 were incorrectly
  allowed, leading to various bad things; including yambar crashing,
  or worse, the compositor crashing
  (https://codeberg.org/dnkl/yambar/issues/129).
* kib/kb, mib/mb and gib/gb formatters were inverted.


### Security
### Contributors

* [sochotnicky](https://codeberg.org/sochotnicky)

## 1.7.0

### Added

* i3: `persistent` attribute, allowing persistent workspaces
  (https://codeberg.org/dnkl/yambar/issues/72).
* bar: `border.{left,right,top,bottom}-width`, allowing the width of
  each side of the border to be configured
  individually. `border.width` is now a short-hand for setting all
  four borders to the same value
  (https://codeberg.org/dnkl/yambar/issues/77).
* bar: `layer: top|bottom`, allowing the layer which the bar is
  rendered on to be changed. Wayland only - ignored on X11.
* river: `all-monitors: false|true`.
* `-d,--log-level=info|warning|error|none` command line option
  (https://codeberg.org/dnkl/yambar/issues/84).
* river: support for the river-status protocol, version 2 (‘urgent’
  views).
* `online` tag to the `alsa` module.
* alsa: `volume` and `muted` options, allowing you to configure which
  channels to use as source for the volume level and muted state.
* foreign-toplevel: Wayland module that provides information about
  currently opened windows.
* alsa: support for capture devices.
* network: `ssid`, `signal`, `rx-bitrate` and `rx-bitrate` tags.
* network: `poll-interval` option (for the new `signal` and
  `*-bitrate` tags).
* tags: percentage tag formatter, for range tags: `{tag_name:%}`.
* tags: kb/mb/gb, and kib/mib/gib tag formatters.
* clock: add a config option to show UTC time.

### Changed

* bar: do not add `spacing` around empty (zero-width) modules.
* alsa: do not error out if we fail to connect to the ALSA device, or
  if we get disconnected. Instead, keep retrying until we succeed
  (https://codeberg.org/dnkl/yambar/issues/86).


### Fixed

* `yambar --backend=wayland` always erroring out with _”yambar was
  compiled without the Wayland backend”_.
* Regression: `{where}` tag not being expanded in progress-bar
  `on-click` handlers.
* `alsa` module causing yambar to use 100% CPU if the ALSA device is
  disconnected (https://codeberg.org/dnkl/yambar/issues/61).


### Contributors

* [paemuri](https://codeberg.org/paemuri)
* [ericonr](https://codeberg.org/ericonr)
* [Nulo](https://nulo.in)


## 1.6.2

### Added

* Text shaping support.
* Support for middle and right mouse buttons, mouse wheel and trackpad
  scrolling (https://codeberg.org/dnkl/yambar/issues/39).
* script: polling mode. See the new `poll-interval` option
  (https://codeberg.org/dnkl/yambar/issues/67).


### Changed

* doc: split up **yambar-modules**(5) into multiple man pages, one for
  each module (https://codeberg.org/dnkl/yambar/issues/15).
* fcft >= 2.4.0 is now required.
* sway-xkb: non-keyboard inputs are now ignored
  (https://codeberg.org/dnkl/yambar/issues/51).
* battery: don’t terminate (causing last status to “freeze”) when
  failing to update; retry again later
  (https://codeberg.org/dnkl/yambar/issues/44).
* battery: differentiate "Not Charging" and "Discharging" in state
  tag of battery module.
  (https://codeberg.org/dnkl/yambar/issues/57).
* string: use HORIZONTAL ELLIPSIS instead of three regular periods
  when truncating a string
  (https://codeberg.org/dnkl/yambar/issues/73).


### Fixed

* Crash when merging non-dictionary anchors in the YAML configuration
  (https://codeberg.org/dnkl/yambar/issues/32).
* Crash in the `ramp` particle when the tag’s value was out-of-bounds
  (https://codeberg.org/dnkl/yambar/issues/45).
* Crash when a string particle contained `{}`
  (https://codeberg.org/dnkl/yambar/issues/48).
* `script` module rejecting range tag end values containing the digit
  `9` (https://codeberg.org/dnkl/yambar/issues/60).


### Contributors

* [novakane](https://codeberg.org/novakane)
* [mz](https://codeberg.org/mz)


## 1.6.1

### Changed

* i3: workspaces with numerical names are sorted separately from
  non-numerically named workspaces
  (https://codeberg.org/dnkl/yambar/issues/30).


### Fixed

* mpd: `elapsed` tag not working (regression, introduced in 1.6.0).
* Wrong background color for (semi-) transparent backgrounds.
* battery: stats sometimes getting stuck at 0, or impossibly large
  values (https://codeberg.org/dnkl/yambar/issues/25).


## 1.6.0

### Added

* alsa: `percent` tag. This is an integer tag that represents the
  current volume as a percentage value
  (https://codeberg.org/dnkl/yambar/issues/10).
* river: added documentation
  (https://codeberg.org/dnkl/yambar/issues/9).
* script: new module, adds support for custom user scripts
  (https://codeberg.org/dnkl/yambar/issues/11).
* mpd: `volume` tag. This is a range tag that represents MPD's current
  volume in percentage (0-100)
* i3: `sort` configuration option, that controls how the workspace
  list is sorted. Can be set to one of `none`, `ascending` or
  `descending`. Default is `none`
  (https://codeberg.org/dnkl/yambar/issues/17).
* i3: `mode` tag: the name of the currently active mode


### Fixed

* YAML parsing error messages being replaced with a generic _“unknown
  error”_.
* Memory leak when a YAML parsing error was encountered.
* clock: update every second when necessary
  (https://codeberg.org/dnkl/yambar/issues/12).
* mpd: fix compilation with clang
  (https://codeberg.org/dnkl/yambar/issues/16).
* Crash when the alpha component in a color value was 0.
* XCB: Fallback to non-primary monitor when the primary monitor is
  disconnected (https://codeberg.org/dnkl/yambar/issues/20)


### Contributors

* [JorwLNKwpH](https://codeberg.org/JorwLNKwpH)
* [optimus-prime](https://codeberg.org/optimus-prime)


## 1.5.0

### Added

* battery: support for drivers that use `charge_*` (instead of
  `energy_*`) sys files.
* removables: SD card support.
* removables: new `ignore` property.
* Wayland: multi-seat support.
* **Experimental**: 'river': new module for the river Wayland compositor.


### Changed

* Requires fcft-2.2.x.
* battery: a poll value of 0 disables polling.


### Fixed

* mpd: check of return value from `thrd_create`.
* battery: handle 'manufacturer' and 'model_name' not being present.
* Wayland: handle runtime scaling changes.
