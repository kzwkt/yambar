test('is-executable', yambar, args: ['--version'])

pwd = meson.current_source_dir()

# Configuration validation tests
test('no-config', yambar, args: ['-C', '-c', 'xyz'], should_fail: true)
test('config-isnt-file', yambar, args: ['-C', '-c', '.'], should_fail: true)
test('config-no-bar', yambar, args: ['-C', '-c', join_paths(pwd, 'no-bar.yml')],
     should_fail: true)
if plugin_alsa_enabled and plugin_backlight_enabled and \
  plugin_battery_enabled and plugin_clock_enabled and \
  plugin_i3_enabled and plugin_mpd_enabled and plugin_network_enabled \
  and plugin_removables_enabled
  test('full-conf-good', yambar, args: ['-C', '-c', join_paths(pwd, 'full-conf-good.yml')])
endif
