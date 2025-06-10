from typing import Set, Dict, Optional

ModuleActivationSettings = Dict[str, Set[str]]


def resolve_module_settings(module_options: str) -> ModuleActivationSettings:
    """
    Filters and configures modules based on user options, using a single-pass logic.

    Args:
        module_options: String containing module options (e.g., "xss,sql:get,-exec").

    Returns:
        A dictionary where keys are module names to be activated, and values are
        sets of HTTP methods for which they are active (empty set means all methods
        or not applicable for passive modules).
        Example: {"xss": {"GET"}, "sql": {"GET", "POST"}, "unsecure_password_passive": set()}
    """

    # Use presets["all"] as the source of all available module names
    available_module_names: Set[str] = set(presets["all"])

    # This structure stores the *desired* state for each module
    # Initialize with all methods active for all explicitly activated modules
    activated_module_methods: Dict[str, Set[str]] = {}

    if module_options is None:
        module_options = "common"
    elif module_options == "":
        return {}  # No modules activated

    for module_opt in module_options.split(","):
        module_opt = module_opt.strip()
        if not module_opt:
            continue

        method_restriction: Optional[str] = None
        is_deactivation = False

        if ":" in module_opt:
            module_name, method_restriction = module_opt.split(":", 1)
            method_restriction = method_restriction.upper()  # Standardize to uppercase (GET, POST)
        else:
            module_name = module_opt

        if module_name.startswith("-"):
            is_deactivation = True
            module_name = module_name[1:]  # Remove the '-' prefix
        elif module_name.startswith("+"):
            module_name = module_name[1:]  # Remove the '+' prefix (explicit activation)

        # Get the actual module names, whether it's a single module or a preset group
        # If module_name_raw is a preset, expand it; otherwise, it's just itself.
        target_modules_list = presets.get(module_name, [module_name])

        for module_name in target_modules_list:
            if module_name not in available_module_names:
                raise ValueError(f"[!] Unable to find a module named {module_name}")

            if is_deactivation:
                # Deactivation logic
                if module_name not in activated_module_methods:
                    # You can't deactivate a module that hasn't been activated yet
                    # This handles cases like "-xss" appearing before "all"
                    # In a single pass, it implies "if previously active".
                    continue

                if not method_restriction:
                    # Deactivate the whole module
                    activated_module_methods.pop(module_name, None)  # Use .pop with default to avoid KeyError
                else:
                    # Deactivate only a specific method for this module
                    if method_restriction in activated_module_methods[module_name]:
                        activated_module_methods[module_name].remove(method_restriction)

                    # If no methods remain active for this module, remove it entirely
                    if not activated_module_methods[module_name]:
                        activated_module_methods.pop(module_name, None)

            else:
                # Activation logic
                if module_name not in activated_module_methods:
                    # If module is not yet in our activated list, add it with default active methods
                    # Default for active modules: both GET and POST.
                    # For passive modules, {"GET", "POST"} simply indicates activation
                    # (methods are irrelevant for passive scan logic, but the module is 'on').
                    activated_module_methods[module_name] = {"GET", "POST"}

                if method_restriction:
                    # If a method restriction is specified, override previous methods to just this one.
                    # This handles cases like "common,xss:post" (xss becomes POST only)
                    activated_module_methods[module_name] = {method_restriction}
                # Else (no method_restriction), keep whatever methods were already set (e.g., from a group)
                # This is important for "common,lfi" where lfi remains {"GET", "POST"}
                # If you want "common" to be overridden by a subsequent non-method-specific activation,
                # e.g., "common,xss" after "xss:get", this requires different logic.
                # Assuming "common" implies all methods unless explicitly restricted later.

    return activated_module_methods


all_modules = {
    "backup",
    "brute_login_form",
    "buster",
    "cookieflags",
    "crlf",
    "cms",
    "csp",
    "csrf",
    "exec",
    "file",
    "htaccess",
    "htp",
    "http_headers",
    "https_redirect",
    "inconsistent_redirection",
    "information_disclosure",
    "ldap",
    "log4shell",
    "methods",
    "network_device",
    "nikto",
    "permanentxss",
    "redirect",
    "shellshock",
    "spring4shell",
    "sql",
    "ssl",
    "ssrf",
    "takeover",
    "timesql",
    "unsecure_password",
    "upload",
    "wapp",
    "wp_enum",
    "xss",
    "xxe"
}

# Modules that will be used if option -m isn't used
common_modules = {
    "cookieflags",
    "csp",
    "exec",
    "file",
    "http_headers",
    "https_redirect",
    "inconsistent_redirection",
    "information_disclosure",
    "permanentxss",
    "redirect",
    "sql",
    "ssl",
    "ssrf",
    "unsecure_password",
    "upload",
    "xss"
}

# Modules that will be used in passive mode -m passive
passive_modules = {
    "cookieflags",
    "csp",
    "http_headers",
    "https_redirect",
    "inconsistent_redirection",
    "information_disclosure",
    "unsecure_password",
}
presets = {
    "all": all_modules,
    "common": common_modules,
    "passive": passive_modules
}
