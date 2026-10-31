"""Quantity registry: what a leaf's free-text kind and unit mean, as a typed quantity.

A leaf names a channel with a kind and a unit as plain strings ("acceleration", "m/s2"). A consumer should not
have to keep its own table to know what those are. This module turns the pair into a typed quantity: a stable kind id, a
physical dimension, the unit as a UCUM code, the value in the kind's coherent SI unit, and a plausibility flag.

It adds information and removes none: the raw kind, unit and value stay in the reading. A kind or a unit that is not
in the registry gets no quantity (None), never a guess. A value outside the plausible range of its kind is flagged
(`in_range` false), not dropped; deciding what to do with it belongs to whoever consumes the reading.

The registry is data. A new kind, or a new unit spelling for an existing kind, is a new entry in KINDS; an
operator can add entries without code through a JSON file (see `load_extra`). Nothing in it depends on a board.
"""

from __future__ import annotations

import json
import math

REGISTRY = "furcate-quantities/1"

# kind -> dimension, SI (coherent) UCUM code, plausible range in SI, and the units a leaf may report:
# leaf unit string -> (UCUM code of that unit, factor to SI, offset to SI), value_si = value * factor + offset.
KINDS: dict[str, dict] = {
    "temperature": {"dimension": "temperature", "si": "K", "range": [0.0, 3000.0],
                    "units": {"celsius": ("Cel", 1.0, 273.15), "kelvin": ("K", 1.0, 0.0)}},
    "pressure": {"dimension": "pressure", "si": "Pa", "range": [0.0, 1.0e8],
                 "units": {"pascal": ("Pa", 1.0, 0.0), "hpa": ("hPa", 100.0, 0.0), "kpa": ("kPa", 1000.0, 0.0)}},
    "humidity": {"dimension": "relative_humidity", "si": "1", "range": [0.0, 1.0],
                 "units": {"percent": ("%", 0.01, 0.0)}},
    "acceleration": {"dimension": "acceleration", "si": "m/s2", "range": [-2000.0, 2000.0],
                     "units": {"m/s2": ("m/s2", 1.0, 0.0), "g": ("[g]", 9.80665, 0.0)}},
    "angular_rate": {"dimension": "angular_rate", "si": "rad/s", "range": [-1.0e4, 1.0e4],
                     "units": {"rad/s": ("rad/s", 1.0, 0.0), "deg/s": ("deg/s", math.pi / 180.0, 0.0)}},
    "magnetic_field": {"dimension": "magnetic_flux_density", "si": "T", "range": [-5.0e-3, 5.0e-3],
                       "units": {"uT": ("uT", 1.0e-6, 0.0), "mT": ("mT", 1.0e-3, 0.0), "T": ("T", 1.0, 0.0)}},
    "gas_resistance": {"dimension": "electrical_resistance", "si": "Ohm", "range": [0.0, 1.0e10],
                       "units": {"ohm": ("Ohm", 1.0, 0.0)}},
    "orientation": {"dimension": "quaternion_component", "si": "1", "range": [-1.0, 1.0],
                    "units": {"unitless": ("1", 1.0, 0.0)}},
    "air_quality_index": {"dimension": "index", "si": "1", "range": [0.0, 1.0e3],
                          "units": {"unitless": ("1", 1.0, 0.0)}},
    "gas_equivalent": {"dimension": "amount_fraction", "si": "1", "range": [0.0, 1.0e6],
                       "units": {"unitless": ("1", 1.0, 0.0), "ppm": ("[ppm]", 1.0, 0.0)}},
    "step_count": {"dimension": "count", "si": "1", "range": [0.0, 1.0e9],
                   "units": {"count": ("1", 1.0, 0.0)}},
    "activity_state": {"dimension": "state", "si": "1", "range": [0.0, 1.0e3],
                       "units": {"count": ("1", 1.0, 0.0)}},
}


def load_extra(path: str) -> int:
    """Adds or replaces kinds from a JSON file shaped like KINDS (units as [ucum, factor, offset]).
    Returns the number of kinds read. A malformed entry raises ValueError and changes nothing."""
    with open(path) as fh:
        extra = json.load(fh)
    staged = {}
    for kind, e in extra.items():
        try:
            lo, hi = e["range"]
            units = {u: (str(v[0]), float(v[1]), float(v[2])) for u, v in e["units"].items()}
            staged[kind] = {"dimension": str(e["dimension"]), "si": str(e["si"]),
                            "range": [float(lo), float(hi)], "units": units}
        except (KeyError, TypeError, ValueError, IndexError) as err:
            raise ValueError("quantity entry %r is malformed: %s" % (kind, err))
    KINDS.update(staged)
    return len(staged)


def quantity(kind, unit, value):
    """-> the quantity dict for a reading, or None when the registry does not know the kind or the unit."""
    k = KINDS.get(kind or "")
    if k is None:
        return None
    u = k["units"].get(unit or "")
    if u is None or isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        return None
    ucum, factor, offset = u
    si = value * factor + offset
    lo, hi = k["range"]
    return {"registry": REGISTRY, "kind": kind, "dimension": k["dimension"], "unit_ucum": ucum, "value": value,
            "si_ucum": k["si"], "si_value": si, "in_range": lo <= si <= hi}


def channel(kind, unit):
    """-> what a channel of this kind and unit is (no value), or None when the registry does not know it."""
    k = KINDS.get(kind or "")
    u = k["units"].get(unit or "") if k else None
    if u is None:
        return None
    return {"registry": REGISTRY, "kind": kind, "dimension": k["dimension"], "unit_ucum": u[0], "si_ucum": k["si"],
            "si_range": list(k["range"])}
