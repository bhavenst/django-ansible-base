import logging
from typing import Any, Optional

from django.contrib.auth.models import AbstractUser
from django.core.exceptions import ValidationError
from django.core.validators import validate_email

from ansible_base.authentication.authenticator_plugins.utils import get_authenticator_plugin
from ansible_base.authentication.models import AuthenticatorUser
from ansible_base.lib.utils.models import is_system_user

logger = logging.getLogger('ansible_base.authentication.utils.user')


def normalize_and_get_email(email: Any) -> Optional[str]:
    """Handles list or string email input, validates type and format, and normalizes it."""
    if not email:
        return None

    normalized = None
    if isinstance(email, list):
        first_email = email[0]
        if not isinstance(first_email, str) or not first_email.strip():
            return None
        normalized = first_email.strip().lower()
    elif isinstance(email, str):
        normalized = email.strip().lower()
    else:
        return None

    if normalized:
        try:
            validate_email(normalized)
        except ValidationError:
            logger.warning("Invalid email address provided by authenticator: '%s'. Setting email to empty.", normalized)
            return None

    return normalized


def can_user_change_password(user: Optional[AbstractUser]) -> bool:
    """
    See if the given user is allowed to change their password.
    True if they are authenticated from the `local` authenticator
    False otherwise.
    The system user can never change their password
    """
    if user is None or is_system_user(user):
        # If we didn't actually get a user we can't say they can change their password
        # Or if we are the system user, we can not change our password ever
        return False

    auth_users = AuthenticatorUser.objects.filter(user=user)
    if auth_users.count() == 0:
        # If the user has no associations we can set a password for them so they can login through the local authenticator
        return True

    for auth_user in auth_users:
        try:
            plugin = get_authenticator_plugin(auth_user.provider.type)
            if plugin.type == 'local':
                return True
        except ImportError:
            pass

    return False
