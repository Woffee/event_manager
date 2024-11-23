from builtins import str
import random


def generate_nickname() -> str:
    """Generate a URL-safe nickname using adjectives and animal names."""
    adjectives = "evil"
    animals = "goose"
    nickname = f"{adjectives}_{animals}_{100}"
    
    return nickname
