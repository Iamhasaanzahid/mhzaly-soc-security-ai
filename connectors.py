#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MHZALY Platform - Connectors Module
Provides shared helper wrappers and utility connectors for external threat intelligence APIs.
"""

import requests
import logging

logger = logging.getLogger(__name__)

def verify_api_connection(service_name: str, endpoint: str, headers: dict = None) -> bool:
    """Helper utility to check connectivity and validity for platform connectors."""
    try:
        resp = requests.get(endpoint, headers=headers, timeout=5)
        return resp.status_code in [200, 401, 403, 429]
    except Exception as e:
        logger.warning(f"Connection check failed for {service_name}: {e}")
        return False
