from django import template

register = template.Library()


@register.filter
def get_item(dictionary, key):
    if not dictionary:
        return None
    return dictionary.get(key)
