yambar-modules-niri-language(5)

# NAME
niri-language - This module provides information about niri's currently
selected language.

# TAGS

[[ *Name*
:[ *Type*
:< *Description*
|  language
:  string
:  The currently selected language.

# CONFIGURATION

No additional attributes supported, only the generic ones (see
*GENERIC CONFIGURATION* in *yambar-modules*(5))

# EXAMPLES

```
bar:
  left:
    - niri-language:
        content:
		  string: {text: "{language}"}
```

# SEE ALSO

*yambar-modules*(5), *yambar-particles*(5), *yambar-tags*(5), *yambar-decorations*(5)

