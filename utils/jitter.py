import time
import random
from dataclasses import dataclass

@dataclass
class JitterConfig:
    enabled: bool = False
    min_delay: float = 0.5
    max_delay: float = 2.0

class Jitter:
    _config = JitterConfig()

    @classmethod
    def configure(cls, enabled: bool, min_delay: float = 0.5, max_delay: float = 2.0):
        cls._config = JitterConfig(enabled, min_delay, max_delay)

    @classmethod
    def wait(cls):
        """Pauses execution for a random interval if jitter is enabled."""
        if cls._config.enabled:
            delay = random.uniform(cls._config.min_delay, cls._config.max_delay)
            time.sleep(delay)