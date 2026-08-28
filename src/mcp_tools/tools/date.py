# -*- coding: utf-8 -*-
"""
Outil: date — Manipulation de dates et heures.
"""

from datetime import datetime, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from typing import Annotated, Optional
from pydantic import Field
from mcp.server.mcpserver import MCPServer, Context
from ..auth.context import check_tool_access
from ..observability import traced_tool


# Formats courants pour le parsing flexible
_PARSE_FORMATS = [
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%Y-%m-%d",
    "%d/%m/%Y %H:%M:%S",
    "%d/%m/%Y %H:%M",
    "%d/%m/%Y",
    "%m/%d/%Y",
    "%d-%m-%Y",
    "%Y%m%d",
    "%Y%m%dT%H%M%S",
]


def _get_tz(tz: Optional[str]) -> ZoneInfo:
    """Résout un fuseau horaire. Défaut = UTC."""
    if not tz:
        return ZoneInfo("UTC")
    try:
        return ZoneInfo(tz)
    except (ZoneInfoNotFoundError, KeyError):
        raise ValueError(f"Fuseau horaire inconnu : '{tz}'. Exemples : UTC, Europe/Paris, America/New_York, Asia/Tokyo")


def _parse_date(date_str: str, tz: Optional[ZoneInfo] = None) -> datetime:
    """Parse une date depuis une string. Essaie ISO 8601 puis formats courants."""
    # Essai fromisoformat (Python 3.11+ gère bien les variantes ISO)
    try:
        dt = datetime.fromisoformat(date_str)
        if dt.tzinfo is None and tz:
            dt = dt.replace(tzinfo=tz)
        return dt
    except ValueError:
        pass

    # Essai des formats courants
    for fmt in _PARSE_FORMATS:
        try:
            dt = datetime.strptime(date_str, fmt)
            if dt.tzinfo is None and tz:
                dt = dt.replace(tzinfo=tz)
            return dt
        except ValueError:
            continue

    raise ValueError(
        f"Format de date non reconnu : '{date_str}'. "
        f"Formats acceptés : ISO 8601 (2026-03-06, 2026-03-06T09:00:00), "
        f"DD/MM/YYYY, YYYYMMDD, etc."
    )


def register(mcp: MCPServer) -> None:

    @mcp.tool()
    @traced_tool("date")
    async def date(
        operation: Annotated[str, Field(description="Opération : now, today, diff, add, format, parse, week_number ou day_of_week")],
        date: Annotated[Optional[str], Field(default=None, description="Date d'entrée en ISO 8601 ou format courant (ex: '2026-03-06', '06/03/2026')")] = None,
        date2: Annotated[Optional[str], Field(default=None, description="Seconde date pour l'opération diff")] = None,
        days: Annotated[Optional[float], Field(default=None, description="Nombre de jours à ajouter (opération add)")] = None,
        hours: Annotated[Optional[float], Field(default=None, description="Nombre d'heures à ajouter (opération add)")] = None,
        minutes: Annotated[Optional[float], Field(default=None, description="Nombre de minutes à ajouter (opération add)")] = None,
        format: Annotated[Optional[str], Field(default=None, description="Format strftime pour l'opération format (ex: '%d/%m/%Y %H:%M')")] = None,
        tz: Annotated[Optional[str], Field(default=None, description="Fuseau horaire IANA (ex: 'Europe/Paris', 'America/New_York', défaut: UTC)")] = None,
        ctx: Optional[Context] = None,
    ) -> dict:
        """Manipulation de dates : now, today, diff, add, format, parse, week_number, day_of_week. Dates en ISO 8601."""
        try:
            check_tool_access("date")

            timezone = _get_tz(tz)

            if operation == "now":
                # Date/heure actuelle dans le fuseau demandé
                now = datetime.now(timezone)
                return {
                    "status": "success",
                    "operation": "now",
                    "datetime": now.isoformat(),
                    "timezone": str(timezone),
                }

            elif operation == "today":
                # Date du jour (sans heure)
                today = datetime.now(timezone).date()
                return {
                    "status": "success",
                    "operation": "today",
                    "date": today.isoformat(),
                    "timezone": str(timezone),
                }

            elif operation == "parse":
                # Parser une date texte → ISO 8601
                if not date:
                    return {"status": "error", "message": "Paramètre 'date' requis pour l'opération 'parse'"}
                dt = _parse_date(date, timezone)
                return {
                    "status": "success",
                    "operation": "parse",
                    "input": date,
                    "datetime": dt.isoformat(),
                    "timezone": str(dt.tzinfo) if dt.tzinfo else "naive",
                }

            elif operation == "format":
                # Reformater une date avec un format strftime
                if not date:
                    return {"status": "error", "message": "Paramètre 'date' requis pour l'opération 'format'"}
                if not format:
                    return {"status": "error", "message": "Paramètre 'format' requis pour l'opération 'format' (ex: '%d/%m/%Y %H:%M')"}
                dt = _parse_date(date, timezone)
                formatted = dt.strftime(format)
                return {
                    "status": "success",
                    "operation": "format",
                    "input": date,
                    "format": format,
                    "result": formatted,
                }

            elif operation == "add":
                # Ajouter une durée à une date
                if not date:
                    return {"status": "error", "message": "Paramètre 'date' requis pour l'opération 'add'"}
                dt = _parse_date(date, timezone)
                delta = timedelta(
                    days=days or 0,
                    hours=hours or 0,
                    minutes=minutes or 0,
                )
                if delta == timedelta(0):
                    return {"status": "error", "message": "Au moins un paramètre de durée requis : days, hours, ou minutes"}
                result = dt + delta
                return {
                    "status": "success",
                    "operation": "add",
                    "input": date,
                    "delta": str(delta),
                    "result": result.isoformat(),
                }

            elif operation == "diff":
                # Différence entre deux dates
                if not date or not date2:
                    return {"status": "error", "message": "Paramètres 'date' et 'date2' requis pour l'opération 'diff'"}
                dt1 = _parse_date(date, timezone)
                dt2 = _parse_date(date2, timezone)
                delta = dt2 - dt1
                total_seconds = delta.total_seconds()
                return {
                    "status": "success",
                    "operation": "diff",
                    "date": dt1.isoformat(),
                    "date2": dt2.isoformat(),
                    "diff_days": delta.days,
                    "diff_seconds": total_seconds,
                    "diff_hours": round(total_seconds / 3600, 2),
                    "diff_human": str(delta),
                }

            elif operation == "week_number":
                # Numéro de semaine ISO
                if not date:
                    # Sans date, utiliser aujourd'hui
                    dt = datetime.now(timezone)
                else:
                    dt = _parse_date(date, timezone)
                iso_cal = dt.isocalendar()
                return {
                    "status": "success",
                    "operation": "week_number",
                    "date": dt.date().isoformat(),
                    "week_number": iso_cal.week,
                    "iso_year": iso_cal.year,
                }

            elif operation == "day_of_week":
                # Jour de la semaine
                if not date:
                    dt = datetime.now(timezone)
                else:
                    dt = _parse_date(date, timezone)
                day_names = {
                    0: "Monday", 1: "Tuesday", 2: "Wednesday",
                    3: "Thursday", 4: "Friday", 5: "Saturday", 6: "Sunday",
                }
                day_names_fr = {
                    0: "Lundi", 1: "Mardi", 2: "Mercredi",
                    3: "Jeudi", 4: "Vendredi", 5: "Samedi", 6: "Dimanche",
                }
                weekday = dt.weekday()
                return {
                    "status": "success",
                    "operation": "day_of_week",
                    "date": dt.date().isoformat(),
                    "day_number": weekday,  # 0=lundi, 6=dimanche (ISO)
                    "day_name_en": day_names[weekday],
                    "day_name_fr": day_names_fr[weekday],
                }

            else:
                return {
                    "status": "error",
                    "message": f"Opération inconnue : '{operation}'. "
                               f"Opérations disponibles : now, today, diff, add, format, parse, week_number, day_of_week",
                }

        except Exception as e:
            return {"status": "error", "message": str(e)}
