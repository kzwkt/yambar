yambar-modules-niri-workspaces(5)

# NAME
niri-workspaces - This module provides information about niri workspaces.

# DESCRIPTION

This module provides a map of each workspace present in niri.

Each workspace has its _id_, _name_, and its status (_focused_,
_active_, _empty_). The workspaces are sorted by their ids.

This module will *only* track the monitor where yambar was launched.
If you have a multi monitor setup, please launch yambar on each
individual monitor to track its workspaces.

# TAGS

[[ *Name*
:[ *Type*
:< *Description*
|  id
:  int
:  The workspace id.
|  name
:  string
:  The name of the workspace.
|  active
:  bool
:  True if the workspace is currently visible on the current output.
|  focused
:  bool
:  True if the workspace is currently focused.
|  empty
:  bool
:  True if the workspace contains no window.

# CONFIGURATION

No additional attributes supported, only the generic ones (see
*GENERIC CONFIGURATION* in *yambar-modules*(5))

# EXAMPLES

```
bar:
  left:
    - niri-workspaces:
        content:
		  map:
		    default: {string: {text: "| {id}"}}
			conditions:
			  active: {string: {text: "-> {id}"}}
			  ~empty: {string: {text: "@ {id}"}}
```

# SEE ALSO

*yambar-modules*(5), *yambar-particles*(5), *yambar-tags*(5), *yambar-decorations*(5)

