yambar-modules-mpris(5)

# NAME
mpris - This module provides MPRIS status such as currently playing artist/album/song

# TAGS

[[ *Name*
:[ *Type*
:< *Description*
|  state
:  string
:  One of *offline*, *stopped*, *paused* or *playing*
|  shuffle
:  bool
:  True if the *shuffle* flag is set
|  repeat
:  string
:  One of *none*, *track* or *paylist*
|  volume
:  range
:  Volume in percentage
|  album
:  string
:  Currently playing album
|  artist
:  string
:  Artist of currently playing song
|  title
:  string
:  Title of currently playing song
|  file
:  string
:  Filename or URL of currently playing song
|  pos
:  string
:  *%M:%S*-formatted string describing the song's current position
   (also see _elapsed_)
|  end
:  string
:  *%M:%S*-formatted string describing the song's total length (also
   see _duration_)
|  elapsed
:  realtime
:  Position in currently playing song, in milliseconds. Can be used
   with a _progress-bar_ particle.

# CONFIGURATION

[[ *Name*
:[ *Type*
:[ *Req*
:< *Description*
|  identities
:  list of string
:  yes
:  A list of MPRIS client identities
|  query_timeout
:  int
:  no
:  Dbus/MPRIS client connection timeout in ms. Try setting/incrementing
   this value if the module reports a timeout error. Defaults to 500.

# EXAMPLES

```
bar:
  center:
    - mpris:
        identities:
          - "spotify"
          - "firefox"
        content:
          map:
            conditions:
              state != offline && state != stopped:
                - string: {text: "{artist}", max: 30 }
                - string: {text: "-" }
                - string: {text: "{title}", max: 30 }
```

# NOTE

The 'identity' refers a part of your clients DBus bus name.
You can obtain a list of active client names using:

```
Systemd:   > busctl --user --list
Playerctl: > playerctl --list-all
Libdbus:   > dbus-send --session --print-reply --type=method_call \
             --dest='org.freedesktop.DBus' /org org.freedesktop.DBus.ListNames
```

MPRIS client bus names start with 'org.mpris.MediaPlayer2.<identity>'.
For example, firefox may use the bus name:
'org.mpris.MediaPlayer2.firefox.instance_1_7' which
gives us the identity 'firefox'

# SEE ALSO

*yambar-modules*(5), *yambar-particles*(5), *yambar-tags*(5), *yambar-decorations*(5)
