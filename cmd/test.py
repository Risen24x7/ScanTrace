app_id = "A0BCA8X0NKG"
# Strip the leading letter
encoded = app_id[1:]  # "A0BCA8X0NKG"
timestamp = int(encoded, 36) / 1000  # convert from ms to seconds

from datetime import datetime, timezone
print(datetime.fromtimestamp(timestamp, tz=timezone.utc))
