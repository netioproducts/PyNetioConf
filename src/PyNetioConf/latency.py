import threading


class LatencyStats:
    """
    Response times of a device's requests, smoothed the way TCP times its round trips (RFC 6298).
    """

    # RFC 6298's gains for the smoothed time and its deviation
    ALPHA = 1 / 8
    BETA = 1 / 4

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.samples = 0
        self.timeouts = 0
        self.smoothed: float | None = None
        self.deviation: float | None = None
        self.last: float | None = None
        self.maximum: float | None = None

    def record(self, seconds: float) -> None:
        """Adds the time a request took from its send to its reply."""
        with self._lock:
            self.samples += 1
            self.last = seconds
            self.maximum = seconds if self.maximum is None else max(self.maximum, seconds)
            if self.smoothed is None or self.deviation is None:
                self.smoothed = seconds
                self.deviation = seconds / 2
            else:
                self.deviation = (1 - self.BETA) * self.deviation + self.BETA * abs(self.smoothed - seconds)
                self.smoothed = (1 - self.ALPHA) * self.smoothed + self.ALPHA * seconds

    def record_timeout(self) -> None:
        """Counts a request that got no reply in time. It doesn't change the times."""
        with self._lock:
            self.timeouts += 1

    def summary(self) -> str:
        with self._lock:
            if self.smoothed is None or self.deviation is None or self.maximum is None:
                return f"no samples, {self.timeouts} timeouts"
            return (
                f"{self.samples} samples, smoothed {self.smoothed * 1000:.0f} ms, deviation "
                f"{self.deviation * 1000:.0f} ms, max {self.maximum * 1000:.0f} ms, {self.timeouts} timeouts"
            )
