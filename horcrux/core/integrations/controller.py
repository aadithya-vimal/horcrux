"""Settings controller and unified command dispatcher for HORCRUX external integrations."""

from __future__ import annotations

import getpass
import json
import logging
from typing import TYPE_CHECKING, Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from horcrux.core.integrations.models import (
    IntegrationCategory,
    IntegrationHealth,
)
from horcrux.core.integrations.registry import get_integration_registry
from horcrux.core.sanitizer import mask_key

if TYPE_CHECKING:
    from horcrux.core.integrations.base import ExternalIntegration
    from horcrux.core.settings import SettingsManager

logger = logging.getLogger("horcrux.settings")


class SettingsController:
    """Authoritative controller and user interface for the unified settings control plane."""

    def __init__(self, console: Console | None = None, settings_manager: SettingsManager | None = None) -> None:
        self.console = console or Console()
        self.registry = get_integration_registry(settings_manager)
        self.settings_manager = self.registry._settings_manager or self._default_settings_manager()

    def _default_settings_manager(self) -> SettingsManager:
        from horcrux.core.settings import get_settings_manager
        return get_settings_manager()

    # ------------------------------------------------------------------
    # Dispatching
    # ------------------------------------------------------------------

    def handle_command(self, args: list[str]) -> int:
        """Route settings CLI arguments to the appropriate unified handler.

        Supported patterns:
          horcrux settings
          horcrux settings status
          horcrux settings [category]
          horcrux settings [category] [provider]
          horcrux settings [category] [provider] [action] [options...]
          horcrux settings provider [name]
          horcrux settings model [model]
          horcrux settings key [provider] [key]
          horcrux settings enable / disable
          horcrux settings budget [num]
          horcrux settings fallback [p1] [p2]...
          horcrux settings reset
        """
        if not args:
            self.render_overview()
            return 0

        sub = args[0].lower()

        # 1. Global / Top-level commands
        if sub in ("status", "diagnostics", "check"):
            return self.render_status()

        if sub in ("doctor", "audit"):
            from horcrux.core.doctor import run_doctor
            run_doctor(self.console)
            return 0

        if sub in ("reset", "defaults"):
            return self._handle_reset()

        if sub == "enable":
            self.settings_manager.settings.enabled = True
            self.settings_manager.save()
            self.console.print("[green][OK][/green] AI & external intelligence enabled globally.")
            return 0

        if sub == "disable":
            self.settings_manager.settings.enabled = False
            self.settings_manager.save()
            self.console.print("[yellow][!][/yellow] AI & external intelligence disabled globally.")
            return 0

        if sub == "budget":
            if len(args) < 2:
                self.console.print(f"Current call budget: [bold cyan]{self.settings_manager.settings.call_budget}[/bold cyan]")
                return 0
            try:
                budget = int(args[1])
                self.settings_manager.settings.call_budget = budget
                self.settings_manager.save()
                self.console.print(f"[green][OK][/green] Call budget set to [bold cyan]{budget}[/bold cyan].")
                return 0
            except ValueError:
                self.console.print("[red]Error: Budget must be an integer.[/red]")
                return 1

        if sub == "fallback":
            if len(args) < 2:
                seq = ", ".join(self.settings_manager.settings.fallback_sequence)
                self.console.print(f"Current fallback sequence: [bold cyan]{seq}[/bold cyan]")
                return 0
            providers = [p.strip().lower() for p in args[1:]]
            self.settings_manager.settings.fallback_sequence = providers
            self.settings_manager.save()
            self.console.print(f"[green][OK][/green] Fallback sequence updated: [bold cyan]{', '.join(providers)}[/bold cyan]")
            return 0

        if sub == "provider":
            if len(args) < 2:
                self.console.print(f"Default AI provider: [bold cyan]{self.settings_manager.settings.default_provider}[/bold cyan]")
                return 0
            prov = args[1].lower()
            integration = self.registry.get(prov)
            if not integration or integration.category != IntegrationCategory.AI:
                self.console.print(f"[yellow]Warning: '{prov}' is not a recognized AI provider. Setting anyway.[/yellow]")
            self.settings_manager.settings.default_provider = prov
            self.settings_manager.save()
            self.console.print(f"[green][OK][/green] Default AI provider set to [bold cyan]{prov}[/bold cyan].")
            return 0

        if sub == "model":
            if len(args) < 2:
                prov = self.settings_manager.settings.default_provider
                current = self.settings_manager.get_model(prov)
                self.console.print(f"Current model for {prov}: [bold cyan]{current}[/bold cyan]")
                return 0
            new_model = args[1]
            prov = self.settings_manager.settings.default_provider
            self.settings_manager.set_model(prov, new_model)
            self.console.print(f"[green][OK][/green] Model for [bold]{prov}[/bold] set to [bold cyan]{new_model}[/bold cyan].")
            return 0

        if sub in ("key", "apikey", "api_key"):
            if len(args) < 3:
                self.console.print("[yellow]Usage: horcrux settings key <provider> <key>[/yellow]")
                return 1
            prov, key = args[1].lower(), args[2]
            self.settings_manager.set_api_key(prov, key)
            self.console.print(f"[green][OK][/green] API key saved for [bold]{prov}[/bold] (masked: {mask_key(key)}).")
            return 0

        # 2. Check if first argument is an Integration Category
        matched_cat = self._match_category(sub)
        if matched_cat:
            cat_args = args[1:]
            return self._handle_category_command(matched_cat, cat_args)

        # 3. Check if first argument is a Provider ID or Tool ID directly (e.g. `settings tenable test` or `settings openai`)
        integration = self.registry.get(sub)
        if integration:
            provider_args = args[1:]
            return self._handle_provider_command(integration, provider_args)

        # Unknown command
        self.console.print(f"[red]Unknown settings command or integration:[/red] '{sub}'")
        self.console.print("Run [bold cyan]horcrux settings[/bold cyan] for overview or [bold cyan]horcrux settings status[/bold cyan] for diagnostics.")
        return 1

    def _match_category(self, name: str) -> IntegrationCategory | None:
        norm = name.lower().replace("-", "_")
        aliases = {
            "ai": IntegrationCategory.AI,
            "llm": IntegrationCategory.AI,
            "vuln": IntegrationCategory.VULNERABILITY,
            "vulnerability": IntegrationCategory.VULNERABILITY,
            "vulnerabilities": IntegrationCategory.VULNERABILITY,
            "engines": IntegrationCategory.VULNERABILITY,
            "tools": IntegrationCategory.SECURITY_TOOLS,
            "security_tools": IntegrationCategory.SECURITY_TOOLS,
            "security": IntegrationCategory.SECURITY_TOOLS,
            "automation": IntegrationCategory.AUTOMATION,
            "browser": IntegrationCategory.AUTOMATION,
            "browsers": IntegrationCategory.AUTOMATION,
            "intelligence": IntegrationCategory.INTELLIGENCE,
            "intel": IntegrationCategory.INTELLIGENCE,
            "general": IntegrationCategory.GENERAL,
        }
        return aliases.get(norm)

    def _handle_category_command(self, category: IntegrationCategory, args: list[str]) -> int:
        """Handle category-scoped command: e.g. `settings vulnerability test` or `settings vulnerability tenable`."""
        if not args:
            self.render_category(category)
            return 0

        first = args[0].lower()

        # Check category-wide actions: status, test, list
        if first in ("status", "diagnostics"):
            return self.render_status(category=category)

        if first in ("test", "test-all"):
            return self._test_all_in_category(category)

        # Look up provider within category
        integration = self.registry.get(first)
        if integration and integration.category == category:
            return self._handle_provider_command(integration, args[1:])

        # Provider might not match or action is unknown
        if integration:
            # Found in another category
            return self._handle_provider_command(integration, args[1:])

        self.console.print(f"[red]Unknown provider '{first}' in category '{category.value}'.[/red]")
        self.render_category(category)
        return 1

    def _handle_provider_command(self, integration: ExternalIntegration, args: list[str]) -> int:
        """Handle provider-scoped commands: e.g. `settings qualys test` or `configure` or `enable`."""
        if not args:
            self.render_provider_detail(integration)
            return 0

        action = args[0].lower()

        if action in ("status", "info"):
            self.render_provider_detail(integration)
            return 0

        if action in ("test", "check", "ping"):
            return self._test_single_integration(integration)

        if action in ("enable", "activate"):
            integration.set_enabled(True)
            self.console.print(f"[green][OK][/green] Enabled [bold]{integration.name}[/bold].")
            return 0

        if action in ("disable", "deactivate"):
            integration.set_enabled(False)
            self.console.print(f"[yellow][!][/yellow] Disabled [bold]{integration.name}[/bold].")
            return 0

        if action in ("remove", "delete", "clear", "purge"):
            integration.remove()
            self.console.print(f"[green][OK][/green] Removed credentials and reset configuration for [bold]{integration.name}[/bold].")
            return 0

        if action in ("configure", "config", "set"):
            return self._configure_integration(integration, args[1:])

        self.console.print(f"[red]Unknown action '{action}' for {integration.name}.[/red]")
        self.console.print(f"Supported actions: [bold]test, configure, enable, disable, remove, status[/bold]")
        return 1

    # ------------------------------------------------------------------
    # Rendering Views
    # ------------------------------------------------------------------

    def render_overview(self) -> None:
        """Render the unified control plane dashboard panel with all integration categories."""
        self.console.print()
        title = Text("HORCRUX CONTROL PLANE - EXTERNAL INTEGRATIONS", style="bold white on blue")
        self.console.print(Panel(title, expand=False, border_style="blue"))

        # 1. Global Core Status
        core_table = Table(title="Global Engine Configuration", show_header=True, header_style="bold cyan")
        core_table.add_column("Setting", style="bold")
        core_table.add_column("Value")
        core_table.add_column("Description")

        s = self.settings_manager.settings
        core_table.add_row(
            "AI Intelligence",
            "[green]ENABLED[/green]" if s.enabled else "[yellow]DISABLED[/yellow]",
            "Global toggle for AI reasoning and synthesis",
        )
        core_table.add_row(
            "Default Provider",
            f"[bold cyan]{s.default_provider}[/bold cyan]",
            f"Active model: {self.settings_manager.get_model(s.default_provider)}",
        )
        core_table.add_row(
            "Call Budget",
            str(s.call_budget),
            "Max AI completions allowed per run",
        )
        core_table.add_row(
            "Fallback Chain",
            " -> ".join(s.fallback_sequence),
            "Multi-provider automatic failover sequence",
        )
        self.console.print(core_table)
        self.console.print()

        # 2. Integration Categories
        for cat in self.registry.categories():
            items = self.registry.list(cat)
            cat_table = Table(title=f"Category: {cat.value.upper()} ({len(items)} registered)", show_header=True, header_style="bold magenta")
            cat_table.add_column("ID", style="bold")
            cat_table.add_column("Name")
            cat_table.add_column("Type")
            cat_table.add_column("Configured")
            cat_table.add_column("Enabled")
            cat_table.add_column("Health / Status")

            for item in items:
                health = item.health_check(quick=True)
                conf_badge = "[green]YES[/green]" if item.is_configured() else "[dim]NO[/dim]"
                en_badge = "[green]ON[/green]" if item.is_enabled() else "[yellow]OFF[/yellow]"
                health_badge = self._format_health(health.health)

                cat_table.add_row(
                    item.id,
                    item.name,
                    item.metadata().provider_type or "standard",
                    conf_badge,
                    en_badge,
                    f"{health_badge} {health.message[:45]}",
                )

            self.console.print(cat_table)
            self.console.print()

        self.console.print("[dim]Commands: horcrux settings status | horcrux settings <category> | horcrux settings <provider> test | horcrux doctor[/dim]")
        self.console.print()

    def render_status(self, category: IntegrationCategory | None = None) -> int:
        """Render complete diagnostics table across all registered integrations."""
        self.console.print()
        scope = f"Category: {category.value.upper()}" if category else "All Categories"
        table = Table(title=f"INTEGRATION HEALTH & DIAGNOSTICS ({scope})", show_header=True, header_style="bold cyan")
        table.add_column("Category", style="magenta")
        table.add_column("Provider ID", style="bold")
        table.add_column("Name")
        table.add_column("Health Status")
        table.add_column("Diagnostics / Detail")

        items = self.registry.list(category)
        for item in items:
            health = item.health_check(quick=True)
            status_badge = self._format_health(health.health)
            table.add_row(
                item.category.value,
                item.id,
                item.name,
                status_badge,
                health.message,
            )

        self.console.print(table)
        self.console.print()
        return 0

    def render_category(self, category: IntegrationCategory) -> None:
        """Render detailed view for a specific category."""
        self.console.print()
        title = Text(f"CATEGORY: {category.value.upper()}", style="bold white on cyan")
        self.console.print(Panel(title, expand=False, border_style="cyan"))

        items = self.registry.list(category)
        table = Table(show_header=True, header_style="bold")
        table.add_column("ID", style="bold")
        table.add_column("Display Name")
        table.add_column("Capabilities")
        table.add_column("Configured")
        table.add_column("Enabled")
        table.add_column("Health")

        for item in items:
            health = item.health_check(quick=True)
            caps = ", ".join(item.capabilities()[:2])
            if len(item.capabilities()) > 2:
                caps += f" (+{len(item.capabilities()) - 2})"

            table.add_row(
                item.id,
                item.name,
                caps or "[dim]none[/dim]",
                "[green]YES[/green]" if item.is_configured() else "[dim]NO[/dim]",
                "[green]ON[/green]" if item.is_enabled() else "[yellow]OFF[/yellow]",
                self._format_health(health.health),
            )

        self.console.print(table)
        self.console.print()
        self.console.print(f"[dim]Run 'horcrux settings {category.value} <provider_id>' to view details or configure.[/dim]")
        self.console.print()

    def render_provider_detail(self, integration: ExternalIntegration) -> None:
        """Render comprehensive provider inspection card."""
        meta = integration.metadata()
        health = integration.health_check(quick=True)
        creds = integration.get_credentials()
        cfg = integration.get_config()

        self.console.print()
        title = Text(f"INTEGRATION: {meta.name} ({meta.id})", style="bold white on blue")
        self.console.print(Panel(title, expand=False, border_style="blue"))

        # Details table
        table = Table(show_header=False, box=None)
        table.add_column("Key", style="bold cyan", width=22)
        table.add_column("Value")

        table.add_row("Canonical ID", meta.id)
        table.add_row("Category", meta.category.value.upper())
        table.add_row("Provider Type", meta.provider_type or "standard")
        table.add_row("Description", meta.description or "N/A")
        if meta.documentation_url:
            table.add_row("Documentation", meta.documentation_url)
        table.add_row("Configured", "[green]YES[/green]" if integration.is_configured() else "[red]NO[/red]")
        table.add_row("Enabled", "[green]ON[/green]" if integration.is_enabled() else "[yellow]OFF[/yellow]")
        table.add_row("Health Status", f"{self._format_health(health.health)} {health.message}")

        # Credentials status
        if meta.credential_fields:
            cred_lines = []
            for f in meta.credential_fields:
                val = creds.get(f.name)
                if val:
                    masked = mask_key(val) if f.secret else val
                    cred_lines.append(f"[green][OK][/green] {f.label or f.name}: {masked}")
                else:
                    req = "[red](REQUIRED)[/red]" if f.required else "[dim](optional)[/dim]"
                    env_hint = f" [dim][env: {', '.join(f.env_vars)}][/dim]" if f.env_vars else ""
                    cred_lines.append(f"[red]✗[/red] {f.label or f.name} {req}{env_hint}")
            table.add_row("Credentials", "\n".join(cred_lines))

        # Config fields
        if meta.config_fields:
            cfg_lines = []
            for cf in meta.config_fields:
                val = cfg.get(cf.name, cf.default)
                cfg_lines.append(f"{cf.label or cf.name}: [bold]{val}[/bold]")
            table.add_row("Configuration", "\n".join(cfg_lines))

        # Capabilities
        caps = meta.capabilities
        if caps:
            table.add_row("Capabilities", ", ".join(caps))

        self.console.print(table)
        self.console.print()
        self.console.print(f"[dim]Actions: horcrux settings {meta.category.value} {meta.id} test | configure | enable | disable | remove[/dim]")
        self.console.print()

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _test_single_integration(self, integration: ExternalIntegration) -> int:
        """Run connection/health probe for a single integration and print result."""
        self.console.print(f"Testing connection to [bold]{integration.name}[/bold]...")
        result = integration.test_connection()

        if result.ok:
            badge = "[bold white on green] OK [/bold white on green]"
            self.console.print(f"{badge} {result.message} [dim]({result.latency_ms:.0f}ms)[/dim]")
            if result.raw_output:
                self.console.print(Panel(result.raw_output, title="Response Snippet", expand=False))
            return 0
        else:
            badge = "[bold white on red] FAILED [/bold white on red]"
            self.console.print(f"{badge} {result.message} [dim]({result.latency_ms:.0f}ms)[/dim]")
            if result.error_type:
                self.console.print(f"  [red]Error Type:[/red] {result.error_type.value}")
            return 1

    def _test_all_in_category(self, category: IntegrationCategory) -> int:
        """Test all configured integrations in a category."""
        items = self.registry.list(category)
        self.console.print(f"Testing {len(items)} integrations in category [bold]{category.value}[/bold]...\n")

        failures = 0
        for item in items:
            if not item.is_configured():
                self.console.print(f"[yellow]SKIPPED[/yellow] {item.name}: Not configured.")
                continue

            res = item.test_connection()
            if res.ok:
                self.console.print(f"[green][OK] PASS[/green]   {item.name} ({res.latency_ms:.0f}ms): {res.message}")
            else:
                self.console.print(f"[red]✗ FAIL[/red]   {item.name} ({res.latency_ms:.0f}ms): {res.message}")
                failures += 1

        self.console.print()
        return 1 if failures > 0 else 0

    def _configure_integration(self, integration: ExternalIntegration, args: list[str]) -> int:
        """Configure credentials and settings for an integration."""
        meta = integration.metadata()
        creds_to_set: dict[str, str] = {}
        config_to_set: dict[str, Any] = {}

        # Check for flags: e.g. --key <val> or --endpoint <val>
        i = 0
        while i < len(args):
            arg = args[i]
            if arg.startswith("--"):
                key = arg.lstrip("-").replace("-", "_")
                val = args[i + 1] if i + 1 < len(args) else ""
                i += 2

                # Match against credential fields
                cred_field = next((f for f in meta.credential_fields if f.name == key), None)
                if cred_field:
                    creds_to_set[key] = val
                    continue

                # Match against config fields
                cfg_field = next((f for f in meta.config_fields if f.name == key), None)
                if cfg_field:
                    config_to_set[key] = val
                    continue

                # Generic config
                config_to_set[key] = val
            else:
                i += 1

        # If no flags passed, provide interactive prompting for credentials
        if not creds_to_set and not config_to_set and meta.credential_fields:
            self.console.print(f"\n[bold cyan]Configuring {meta.name}[/bold cyan]")
            self.console.print("[dim]Press Enter to skip / keep current value.[/dim]\n")

            existing_creds = integration.get_credentials()
            for field in meta.credential_fields:
                curr = existing_creds.get(field.name, "")
                prompt_txt = f"{field.label or field.name}"
                if curr:
                    prompt_txt += f" [current: {mask_key(curr) if field.secret else curr}]"
                prompt_txt += ": "

                if field.secret:
                    try:
                        entered = getpass.getpass(prompt_txt)
                    except Exception:
                        entered = input(prompt_txt)
                else:
                    entered = input(prompt_txt)

                if entered.strip():
                    creds_to_set[field.name] = entered.strip()

            for cf in meta.config_fields:
                curr = integration.get_config().get(cf.name, cf.default or "")
                prompt_txt = f"{cf.label or cf.name} [current: {curr}]: "
                entered = input(prompt_txt)
                if entered.strip():
                    config_to_set[cf.name] = entered.strip()

        # Save updates
        integration.configure(credentials=creds_to_set or None, config=config_to_set or None)
        self.console.print(f"[green][OK][/green] Successfully updated configuration for [bold]{meta.name}[/bold].")
        return 0

    def _handle_reset(self) -> int:
        """Reset settings to default."""
        from horcrux.core.settings import HorcruxSettings
        defaults = HorcruxSettings.default()
        self.settings_manager.save(defaults)
        self.console.print("[green][OK][/green] All settings reset to default values.")
        return 0

    def _format_health(self, health: IntegrationHealth) -> str:
        """Format an IntegrationHealth enum to a colored Rich badge."""
        badges = {
            IntegrationHealth.HEALTHY: "[green]* HEALTHY[/green]",
            IntegrationHealth.OPERATIONAL: "[green]* OPERATIONAL[/green]",
            IntegrationHealth.CONFIGURED: "[cyan]* CONFIGURED[/cyan]",
            IntegrationHealth.CONNECTIVITY_VERIFIED: "[green]* VERIFIED[/green]",
            IntegrationHealth.AUTHENTICATED: "[green]* AUTHENTICATED[/green]",
            IntegrationHealth.DEGRADED: "[yellow]^ DEGRADED[/yellow]",
            IntegrationHealth.UNHEALTHY: "[red][X] UNHEALTHY[/red]",
            IntegrationHealth.UNAVAILABLE: "[dim]o UNAVAILABLE[/dim]",
            IntegrationHealth.NOT_CONFIGURED: "[dim]o NOT CONFIGURED[/dim]",
            IntegrationHealth.UNKNOWN: "[dim]? UNKNOWN[/dim]",
        }
        return badges.get(health, f"[dim]{health.value}[/dim]")
