project('c3 test', 'vala', 'c')

dependencies = [
  dependency('glib-2.0'),
  dependency('gobject-2.0'),
  dependency('json-glib-1.0'),
  dependency('gee-0.8'),
  meson.get_compiler('vala').find_library('posix'),
  ]

sources = files('c3.vala')

executable('tst', sources, dependencies: dependencies)

