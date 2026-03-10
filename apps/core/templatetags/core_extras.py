from django import template
import json

register = template.Library()

@register.filter
def get_item(mapping, key):
    try:
        return mapping.get(key)
    except Exception:
        return None

@register.filter
def to_json(value):
    return json.dumps(value)

@register.filter
def heat_class(score):
    try:
        score = int(score)
    except Exception:
        score = 0
    if score <= 20:
        return "heat-critical"
    if score <= 40:
        return "heat-high"
    if score <= 60:
        return "heat-medium"
    if score <= 80:
        return "heat-low"
    return "heat-good"

@register.filter
def ampel_class(score):
    try:
        score = int(score)
    except Exception:
        score = 0
    if score <= 20:
        return "bg-danger"
    if score <= 40:
        return "bg-warning"
    if score <= 80:
        return "bg-primary"
    return "bg-success"

@register.filter
def priority_badge(priority):
    mapping = {
        "CRITICAL": "text-bg-danger",
        "HIGH": "text-bg-warning",
        "MEDIUM": "text-bg-primary",
        "LOW": "text-bg-success",
    }
    return mapping.get(str(priority or '').upper(), 'text-bg-secondary')
