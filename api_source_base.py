import requests

class APISourceBase:
    def __init__(self, config):
        self.config = config
        self.session = self.create_session()
    
    def create_session(self):
        """Override in subclasses if needed (e.g. custom auth)."""
        return requests.Session()
    
    def fetch_events(self):
        """Override in subclass. Should yield (events, to_time)."""
        raise NotImplementedError("Subclasses must implement fetch_events()")
    
    def compute_unique_id(self, event):
        """Override for custom deduplication logic if needed."""
        raise NotImplementedError("Subclasses must implement compute_unique_id()")
