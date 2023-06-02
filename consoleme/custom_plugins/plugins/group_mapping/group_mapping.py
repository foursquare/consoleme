"""Group mapping plugin."""
import boto3
import traceback
import sys
import time
import yaml
import base64
from typing import List, Dict
from cryptography.fernet import Fernet

import sentry_sdk
import simplejson as json
from redis.exceptions import ConnectionError

from consoleme.config import config
from consoleme.lib.account_indexers import get_account_id_to_name_mapping
from consoleme.lib.cloud_credential_authorization_mapping import (
    CredentialAuthorizationMapping,
)
from consoleme.lib.cloud_credential_authorization_mapping.models import (
    RoleAuthorizations,
    user_or_group
)
from consoleme.lib.crypto import Crypto
from consoleme.lib.plugins import get_plugin_by_name
from consoleme.lib.redis import RedisHandler

log = config.get_logger("consoleme")
aws = get_plugin_by_name(config.get("plugins.aws", "default_aws"))()
stats = get_plugin_by_name(config.get("plugins.metrics", "default_metrics"))()
credential_authz_mapping = CredentialAuthorizationMapping()

# TODO: Docstrings should provide examples of the data that needs to be returned


class GroupMapping:
    """Group mapping handles mapping groups to eligible roles and accounts."""

    def __init__(self):
        pass

    async def get_eligible_roles(
        self, username: str, groups: list, user_role: str, console_only: bool, **kwargs
    ) -> list:
        """Get eligible roles for user."""
        roles: list = []
        # Legacy cruft, we should rename the parameter here.
        include_cli: bool = not console_only

        roles.extend(
            await credential_authz_mapping.determine_users_authorized_roles(
                username, groups, include_cli
            )
        )

        return list(set(roles))

    @staticmethod
    async def filter_eligible_roles(query: str, obj: object) -> List:
        selected_roles: List = []
        for r in obj.eligible_roles:
            if query.lower() == r.lower():
                # Exact match. Only return the specific role
                return [r]
            if query.lower() in r.lower():
                selected_roles.append(r)
        return list(set(selected_roles))

    async def set_recent_user(self, user):
        pass

    async def set_console_roles_in_cache(
        self,
        user,
        roles,
        expiration=config.get("group_mapping_config.role_cache_expiration", 21600),
    ):
        """Set roles in cache with a nominal expiration"""
        stats.count("set_console_roles_in_cache")
        if not self.red:
            self.red = await RedisHandler().redis()
        expiration = int(time.time()) + expiration
        role_blob = json.dumps({"user": user, "roles": roles, "expiration": expiration})
        crypto = Crypto()
        sig = crypto.sign(role_blob)

        key = config.get(
            "group_mapping_config.role_cache_redis_key", "ROLE_CACHE_{}"
        ).format(user)
        sig_key = config.get(
            "group_mapping_config.role_cache_redis_sig_key", "ROLE_CACHE_SIG_{}"
        ).format(user)

        try:
            self.red.setex(key, expiration, role_blob)
            self.red.setex(sig_key, expiration, sig)
        except ConnectionError:
            log.error("Error connecting to Redis.", exc_info=True)

    async def get_roles_from_cache(self, user):
        """Get roles from cache"""
        stats.count("get_roles_from_cache")

        key = config.get(
            "group_mapping_config.role_cache_redis_key", "ROLE_CACHE_{}"
        ).format(user)
        sig_key = config.get(
            "group_mapping_config.role_cache_redis_sig_key", "ROLE_CACHE_SIG_{}"
        ).format(user)

        if not self.red:
            self.red = await RedisHandler().redis()

        role_r = self.red.get(key)
        if not role_r:
            return []

        role_sig = self.red.get(sig_key)

        if not role_sig:
            stats.count("get_roles_from_cache.no_role_sig")
            log.error("Role data is in redis, but no signature is present.")
            return []

        role_blob = json.loads(role_r)

        if int(time.time()) > role_blob.get("expiration", 0):
            stats.count("get_roles_from_cache.role_cache_expired")
            log.error("Role cache for {} has expired.".format(user))
            return []

        if role_blob.get("user") != user:
            stats.count("get_roles_from_cache.role_cache_user_invalid")
            log.error(
                "Role cache user mismatch. Cache has: {}. User requested is {}".format(
                    role_blob.get("user"), user
                )
            )
            return []
        return role_blob.get("roles")

    async def generate_credential_authorization_mapping(self, authorization_mapping):
        # Override this with company-specific logic
        kms = boto3.client('kms', region_name='us-east-1')
        s3 = boto3.client('s3', region_name='us-east-1')
        encrypted_file_path = config.get("group_mapping.s3_mapping_file_path")
        plaintext_file = "role_mapping.decrypted"
        mapping_bucket = config.get("group_mapping.s3_mapping_bucket")

        NUM_BYTES_FOR_LEN = 5
        
        authorization_mapping: Dict[user_or_group, RoleAuthorizations] = dict()

        # pull from s3
        encrypted_file = encrypted_file_path.split("/")[-1]
        try:
            with open(encrypted_file, 'wb') as s3_file:
                s3.download_fileobj(mapping_bucket, encrypted_file_path, s3_file)
        except Exception:
            log.error("ERROR downloading s3 encrypted file")
            log.error(traceback.print_exc())
            return None
    
        try:
            with open(encrypted_file, 'rb') as infile:
                encrypted_mapping_data = infile.read()

            key_encrypted_len = int.from_bytes(encrypted_mapping_data[:NUM_BYTES_FOR_LEN], byteorder='big') + NUM_BYTES_FOR_LEN
            key_encrypted = encrypted_mapping_data[NUM_BYTES_FOR_LEN:key_encrypted_len]
        except Exception:
            log.error("ERROR reading encrypted file")
            log.error(traceback.print_exc())
            return None


        # Decrypt the data key before using it
        try:
            key_plaintext = kms.decrypt(CiphertextBlob=key_encrypted)['Plaintext']
            if key_plaintext is None:
                log.error("ERROR decrypting data key returned none")
                return None
        except Exception:
            log.error("ERROR decrypting data key")
            log.error(traceback.print_exc())
            return None

        # decrypt file
        try:
            key_64encoded = base64.b64encode(key_plaintext)
            f = Fernet(key_64encoded)
            decrypted_mapping_contents = f.decrypt(encrypted_mapping_data[key_encrypted_len:])
        except Exception:
            log.error("ERROR decrypting mapping file")
            log.error(traceback.print_exc())
            return None

        # Write the decrypted file contents
        try:
            with open(plaintext_file, 'wb') as file_decrypted:
                file_decrypted.write(decrypted_mapping_contents)
        except Exception:
            log.error("ERROR writing decrypted data")
            log.error(traceback.print_exc())
            return None

        loaded_mapping = yaml.load(open(plaintext_file, 'r'), Loader=yaml.SafeLoader)
        # log.error(json.dumps(loaded_mapping))
        for group, role_mapping in loaded_mapping.items():
            authorization_mapping[group] = RoleAuthorizations.parse_obj(
                {"authorized_roles": set(), "authorized_roles_cli_only": set()}
            )
            authorization_mapping[group].authorized_roles.update(
                role_mapping.get("authorized_roles", [])
            )
            authorization_mapping[group].authorized_roles_cli_only.update(
                role_mapping.get("authorized_roles_cli_only", [])
            )
        log.info("successfully loaded role mappings")
        return authorization_mapping

    async def get_eligible_accounts(self, role_arns):
        """Get eligible accounts for user."""
        stats.count("get_eligible_accounts")
        account_ids = {}

        friendly_names = await get_account_id_to_name_mapping()
        for r in role_arns:
            try:
                account_id = r.split(":")[4]
                account_friendlyname = friendly_names.get(account_id, "")
                if account_friendlyname and isinstance(account_friendlyname, list):
                    account_ids[account_id] = account_friendlyname[0]
                elif account_friendlyname and isinstance(account_friendlyname, str):
                    account_ids[account_id] = account_friendlyname
            except Exception as e:
                log.error(
                    {
                        "function": f"{__name__}.{sys._getframe().f_code.co_name}",
                        "message": "Unable to parse role ARN",
                        "role": r,
                        "error": str(e),
                    }
                )
                sentry_sdk.capture_exception()
        return account_ids

    async def get_account_mappings(self) -> dict:
        """Get a dictionary with all of the account mappings (friendly names -> ID and ID -> names)."""
        return {}

    async def get_secondary_approvers(self, group, return_default=False):
        return config.get("access_requests.default_approver")

    def get_account_names_to_ids(self, force_refresh: bool = False) -> dict:
        """Get account name to id mapping"""
        stats.count("get_account_names_to_ids")
        return {}

    def get_account_ids_to_names(self, force_refresh: bool = False) -> str:
        """Get account id to name mapping"""
        stats.count("get_account_ids_to_names")
        return {}

    async def get_max_cert_age_for_role(self, role_name: str):
        """Retrieve the maximum allowed certificate age allowable to retrieve a particular
        role. 30 will be returned if there is no max age defined.
        """
        return 360

    async def get_all_account_data(self):
        return {}

    async def get_all_accounts(self):
        """Get all account details"""
        return {}

    async def get_all_user_groups(self, user, groups):
        return []

    def is_role_valid(self, entry):
        return True


def init():
    """Initialize group_mapping plugin."""
    return GroupMapping()
