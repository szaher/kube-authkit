"""
Authentication strategies for Kubernetes/OpenShift.

This package contains concrete implementations of various authentication
strategies, all implementing the AuthStrategy interface defined in base.py.
"""

from .base import AuthStrategy

__all__ = ["AuthStrategy"]
