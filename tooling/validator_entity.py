import logging as log
from collections import Counter

from oidfed.commons import *
from oidfed.validator_errors import *

# Define common claim names to check for misspellings
COMMON_CLAIM_NAMES_TYPOS = {
    "trust_mark_issuers": ["trust_marks_issuers", "trust_mark_issuer", "trust_marks_issuer"],
    "metadata_policy": ["metadata_policies", "metadatapolicy"],
    "metadata_policy_crit": ["metadata_policies_crit", "metadata_policy_critical"]
}

# Define known claims for each statement type
COMMON_CLAIM_NAMES = {
    "iss", "sub", "iat", "exp", "jwks", "metadata", "trust_marks"
}

COMMON_EC_CLAIM_NAMES = COMMON_CLAIM_NAMES | {
    "authority_hints", "trust_mark_issuers"
}

COMMON_SS_CLAIM_NAMES = COMMON_CLAIM_NAMES | {
    "metadata_policy", "metadata_policy_crit", "source_endpoint", "constraints", "authority_hints"
}

# Specific claims that Trust Anchors should not have
FORBIDDEN_TA_CLAIMS = {"metadata_policy", "source_endpoint"}

# Lifetime limits
LIFETIME_UPPER_BOUND = timedelta(days=90)
LIFETIME_LOWER_BOUND = timedelta(minutes=5)


def check_entity_statement(entity):
    entity_id = entity['entity_id']
    log.debug(f"Checking entity: {entity_id}")

    # Extract all data
    parent_id = entity['parent_id']
    statement_type = entity['statement_type']
    entity_type = entity['entity_type']
    entity_type_org = entity['entity_type_org']
    request_time = entity['request_time']
    entity_data = entity['entity_data']
    entity_depth = entity['entity_depth'] if 'entity_depth' in entity else None
    entity_instances = entity['entity_instances'] if 'entity_instances' in entity else None
    header = entity_data["header"]
    cty_claim = header.get('cty', None)
    payload = entity_data["payload"]

    results = {
        'entity_id': entity_id,
        'parent_id': parent_id,
        'statement_type': statement_type,
        'entity_type': entity_type,
        'entity_type_org': entity_type_org,
        'request_time': request_time,
        'entity_depth': entity_depth,
        'entity_instances': entity_instances,
        'entity_header_cty': cty_claim,
        'warnings': [],
        'errors': [],
        'errors_transformer': [],
        'errors_trust_marks': {},
        'trust_mark_header_typs': [],
    }

    # Check signature
    check_es_signature(entity_data, results)

    # Check header
    check_header(header, results)

    # Check entity identifier
    check_entity_identifier(entity_id, results, url=True, host=True, no_query=True, no_fragment=True)

    # Check payload required claims
    check_required_claims(payload, results, request_time, statement_type)

    # Check for invalid claims
    check_invalid_claims(payload, results, statement_type)

    # Check for additional claims not present in the OpenID Federation spec
    check_unexpected_claims(payload, results, statement_type)

    # Check jwks
    check_all_jwks(payload, results)

    # Check authority_hints
    check_authority_hints(payload, results, statement_type)

    # Check trust_marks if present
    check_trust_marks(payload["trust_marks"], results, statement_type) if "trust_marks" in payload else None

    # Check constraints if present
    check_constraints(payload["constraints"], results) if "constraints" in payload else None

    # Check metadata
    check_metadata(payload, results, statement_type)

    # Check metadata_policy (for subordinate statements)
    check_metadata_policy(payload["metadata_policy"], results) if statement_type == STATEMENT_TYPE_SS and "metadata_policy" in payload else None

    # Process transformer errors
    if entity_data['errors']:
        add_error(results, ERR_TRANSFORMER_ERROR)
        results['errors_transformer'] = entity_data['errors']

    # Process trust mark errors
    if results['errors_trust_marks']:
        add_error(results, ERR_TRUST_MARK_ERROR)

    return results


def check_es_signature(entity_data, results):
    if not 'signature_valid' in entity_data:
        log.error('Missing signature_valid attribute in entity statement, check data transformation!')
        return
    if not entity_data['signature_valid']:
        add_error(results, ERR_ENTITY_STATEMENT_SIGNATURE_INVALID)


def check_header(header, results):

    # Check typ header
    if "typ" not in header:
        add_error(results, ERR_MISSING_TYP_HEADER_PARAMETER)
    elif header["typ"] != ENTITY_STATEMENT_JWT_TYP:
        add_error(results, ERR_INVALID_TYP_HEADER)

    # Check alg header
    if "alg" not in header:
        add_error(results, ERR_MISSING_ALG_HEADER_PARAMETER)
    elif header["alg"] == "none":
        add_error(results, ERR_INVALID_ALG_HEADER_PARAMETER)

    # Check kid header
    if "kid" not in header:
        add_error(results, ERR_MISSING_KID_HEADER_PARAMETER)


def check_entity_identifier(entity_id, results, url=True, https=True, host=True, no_query=True, no_fragment=True):

    # Check for URL scheme
    if https and not entity_id.startswith("https://"):
        add_error(results, ERR_ENTITY_ID_MUST_USE_HTTPS)
        return

    # Parse the URL to check its components
    if url:
        try:
            from urllib.parse import urlparse
            parsed_url = urlparse(entity_id)

            # Check for host component
            if host and not parsed_url.netloc:
                add_error(results, ERR_ENTITY_ID_MUST_HAVE_HOST)

            # Check for query
            if no_query and parsed_url.query:
                add_error(results, ERR_ENTITY_ID_MUST_NOT_CONTAIN_QUERY)

            # check for fragment
            if no_fragment and parsed_url.fragment:
                add_error(results, ERR_ENTITY_ID_MUST_NOT_CONTAIN_FRAGMENTS)

        except Exception as e:
            add_error(results, ERR_INVALID_ENTITY_ID_URL_FORMAT)


def check_required_claims(payload, results, request_time, statement_type):
    # Check iss
    if "iss" in payload:
        results["iss"] = payload["iss"]
    else:
        add_error(results, ERR_MISSING_ISS_CLAIM)

    # Check sub
    if "sub" in payload:
        results["sub"] = payload["sub"]
    else:
        add_error(results, ERR_MISSING_SUB_CLAIM)

    if 'sub' in payload and 'iss' in payload:
        is_self_issued = payload["iss"] == payload["sub"]
        results["is_self_issued"] = is_self_issued

        # Statement type validation
        if statement_type == STATEMENT_TYPE_EC and not is_self_issued:
            add_error(results, ERR_ENTITY_CONFIG_ISS_MUST_EQUAL_SUB)
        elif statement_type == STATEMENT_TYPE_SS and is_self_issued:
            add_error(results, ERR_SUBORDINATE_ISS_MUST_DIFFER_FROM_SUB)

    if 'iat' in payload:
        results["iat_time"] = payload["iat"]
    else:
        add_error(results, ERR_MISSING_IAT_CLAIM)

    if 'exp' in payload:
        results["exp_time"] = payload["exp"]
    else:
        add_error(results, ERR_MISSING_EXP_CLAIM)

    # Check iat and exp
    if 'iat' in payload and 'exp' in payload and payload['iat'] and payload['exp']:

        iat = unix_time_to_date(payload["iat"])
        exp = unix_time_to_date(payload["exp"])
        lifetime = exp - iat

        results["lifetime"] = int(lifetime.total_seconds())
        results["lifetime_days"] = lifetime.days

        if lifetime > LIFETIME_UPPER_BOUND:
            add_warning(results, WARN_ENTITY_STATEMENT_LONG_LIVED)

        elif lifetime < LIFETIME_LOWER_BOUND:
            add_warning(results, WARN_ENTITY_STATEMENT_SHORT_LIVED)

        if request_time and request_time > 1744588800:  # Exact time of retrieval / Only validate after 2025-04-14
            # if payload["iat"] == payload["exp"] == 0:
            #     add_warning(results, WARN_ENTITY_STATEMENT_ZERO_IAT_EXP)

            ret = unix_time_to_date(request_time)

            if ret < (iat - JWT_LEEWAY_FINE):
                add_error(results, ERR_ENTITY_STATEMENT_ISSUED_IN_FUTURE)
            if (exp + JWT_LEEWAY_FINE) < ret:
                add_error(results, ERR_ENTITY_STATEMENT_EXPIRED)
        else:
            add_warning(results, WARN_UNABLE_TO_VALIDATE_LIFETIME)


def check_invalid_ta_claims(payload, results):
    if "authority_hints" in payload:
        add_error(results, ERR_TRUST_ANCHORS_MUST_NOT_HAVE_AUTHORITY_HINTS)

    if set(payload) & FORBIDDEN_TA_CLAIMS:
        add_error(results, ERR_INVALID_CLAIM_IN_TRUST_ANCHOR)  # beim TA


def check_invalid_claims(payload, results, statement_type):
    # For Entity Configurations
    if statement_type == STATEMENT_TYPE_EC:
        # Entity Configurations must not contain constraints
        if "constraints" in payload:
            add_error(results, ERR_CONSTRAINTS_CLAIM_NOT_ALLOWED_IN_ENTITY_CONFIG)

        # Entity Configurations must not contain metadata_policy
        if "metadata_policy" in payload:
            add_error(results, ERR_METADATA_POLICY_NOT_ALLOWED_IN_ENTITY_CONFIG)

        # Entity Configurations must not contain metadata_policy_crit
        if "metadata_policy_crit" in payload:
            add_error(results, ERR_METADATA_POLICY_CRIT_NOT_ALLOWED_IN_ENTITY_CONFIG)

        # Check for Trust Anchor specifics only if it's a known Trust Anchor
        if is_known_ta(payload["sub"]):
            check_invalid_ta_claims(payload, results)

    # For Subordinate Statements
    if statement_type == STATEMENT_TYPE_SS:
        # authority_hints must not be present in subordinate statements
        if "authority_hints" in payload:
            add_error(results, ERR_AUTHORITY_HINTS_NOT_ALLOWED_IN_SUBORDINATE)

        # trust_mark_issuers must not be present in subordinate statements
        if "trust_mark_issuers" in payload:
            add_error(results, ERR_TRUST_MARK_ISSUERS_NOT_ALLOWED_IN_SUBORDINATE)

        # trust_mark_owners must not be present in subordinate statements
        if "trust_mark_owners" in payload:
            add_error(results, ERR_TRUST_MARK_OWNERS_NOT_ALLOWED_IN_SUBORDINATE)

        # source_endpoint is optional in the latest specification
        if "source_endpoint" in payload and not payload["source_endpoint"].startswith("https://"):
            add_error(results, ERR_SOURCE_ENDPOINT_MUST_USE_HTTPS)

    # Check for misspelled claims in both types
    for _, misspellings in COMMON_CLAIM_NAMES_TYPOS.items():
        for misspelled in misspellings:
            if misspelled in payload:
                add_warning(results, WARN_POSSIBLE_MISSPELLED_CLAIM)


def check_unexpected_claims(payload, results, statement_type):

    # Determine which set of known claims to use
    if statement_type == STATEMENT_TYPE_EC:
        known_claims = COMMON_EC_CLAIM_NAMES
    elif statement_type == STATEMENT_TYPE_SS:  # subordinate_statement
        known_claims = COMMON_SS_CLAIM_NAMES
    else:
        log.error(f'Unknown entity class: {statement_type}')
        return

    # Find unexpected claims
    unexpected_claims = list(set(payload) - known_claims)

    if unexpected_claims:
        add_warning(results, WARN_UNEXPECTED_CLAIMS_FOUND)

        # Store the unexpected claims in the results for reporting
        results["unexpected_claims"] = unexpected_claims


def check_jwks(jwks):
    warnings = []
    errors = []

    # Check if jwks is a proper structure
    if not isinstance(jwks, dict) or "keys" not in jwks or not jwks['keys']:
        errors.append(ERR_INVALID_JWKS_STRUCTURE)
        return warnings, errors

    jwks_keys = jwks["keys"]

    # Check for uniqueness of keys
    kid_values = [k["kid"] for k in jwks_keys if isinstance(k, dict) and "kid" in k]
    duplicate_kids = [kid for kid, count in Counter(kid_values).items() if count > 1]

    if duplicate_kids:
        errors.append(ERR_NON_UNIQUE_KID_VALUE)

    # Check each key for kid
    for key in jwks_keys:
        if not isinstance(key, dict):
            errors.append(ERR_INVALID_KEY_IN_JWKS)
            continue

        if "kid" not in key:
            errors.append(ERR_MISSING_KID_IN_KEY)
            continue

        # Check for thumbprint recommendation
        if not looks_like_jwk_thumbprint(key["kid"]):
            warnings.append(WARN_KEY_ID_NOT_JWK_THUMBPRINT)

    return warnings, errors


def check_all_jwks(payload, results):
    # All Entity Statements require jwks
    if "jwks" not in payload:
        add_error(results, ERR_MISSING_JWKS_CLAIM)
        return

    # Check entity JWKS
    jwks = payload["jwks"]
    jwks_warnings, jwks_errors = check_jwks(jwks)

    for warning in jwks_warnings:
        add_warning(results, warning)

    for error in jwks_errors:
        add_error(results, error)

    # Check entity metadata JWKs
    if not 'metadata' in payload or not payload['metadata']:
        return

    metadata_keys = {}
    metadata = payload['metadata']

    for entity_type, type_metadata in metadata.items():
        if not isinstance(type_metadata, dict):
            continue
        jwks_extensions = KNOWN_JWKS_EXTENSIONS & set(type_metadata)

        if entity_type == ENTITY_TYPE_FE:
            if jwks_extensions:
                add_error(results, ERR_JWKS_EXTENSIONS_IN_FEDERATION_ENTITY_METADATA)
        else:
            if len(jwks_extensions) > 2:
                add_warning(results, WARN_MULTIPLE_JWKS_EXTENSIONS_IN_ENTITY_METADATA)

            # Since this check if offline, only JWKS are tested here -> TODO
            if 'jwks' in type_metadata:
                jwks = type_metadata["jwks"]
                metadata_jwks_warnings, metadata_jwks_errors = check_jwks(jwks)

                if metadata_jwks_warnings:
                    add_warning(results, WARN_WARNING_IN_ENTITY_METADATA_JWKS)
                if metadata_jwks_errors:
                    add_error(results, ERR_ERROR_IN_ENTITY_METADATA_JWKS)

                if type_metadata['jwks'] and 'keys' in type_metadata['jwks'] and type_metadata['jwks']['keys']:
                    metadata_keys[entity_type] = type_metadata['jwks']['keys']

    entity_keys = jwks.get('keys', [])
    if entity_keys:  # only check reuse if entity has own keys, which it must have
        for entity_type, key_list in metadata_keys.items():
            reused_keys = [key for key in key_list if key in entity_keys]
            if reused_keys:  # reused keys
                add_warning(results, WARN_JWK_REUSE_IN_ENTITY_TYPE_METADATA)
                break


def check_authority_hints(payload, results, statement_type):

    # Only process ECs
    if statement_type != STATEMENT_TYPE_EC:
        return

    has_auth_hints = "authority_hints" in payload

    # Trust Anchors
    if is_known_ta(payload['sub']):
        if has_auth_hints:
            add_error(results, WARN_TRUST_ANCHOR_WITH_AUTHORITY_HINTS)
    else:
        # Regular entity with authority_hints
        if has_auth_hints:
            if not payload["authority_hints"]:
                add_error(results, ERR_EMPTY_AUTHORITY_HINTS_ARRAY_NOT_ALLOWED)
            elif not isinstance(payload["authority_hints"], list):
                add_error(results, ERR_AUTHORITY_HINTS_MUST_BE_ARRAY)
            else:
                # Check each authority hint is a string
                for i, hint in enumerate(payload["authority_hints"]):
                    if not isinstance(hint, str):
                        add_error(results, ERR_AUTHORITY_HINT_MUST_BE_STRING)
        else:
            add_warning(results, WARN_ENTITY_CONFIG_NO_AUTHORITY_HINTS)


def check_trust_mark_header(results, i, trust_mark):
    # No need to check alg here -> Already handled in transformer, could not be decoded otherwise
    header = trust_mark['trust_mark']['header']

    if not 'kid' in header:
        add_tm_error(results, i, ERR_TRUST_MARK_NO_KID_IN_HEADER)

    if not 'typ' in header:
        add_tm_error(results, i, ERR_TRUST_MARK_NO_TYP_IN_HEADER)
    else:
        results['trust_mark_header_typs'] = [header['typ']]
        if header['typ'] == TRUST_MARK_JWT_TYP:
            return
        elif header['typ'] == ENTITY_STATEMENT_JWT_TYP:
            add_tm_error(results, i, ERR_TRUST_MARK_WRONG_TYP_IN_HEADER)
        else:
            add_tm_error(results, i, ERR_TRUST_MARK_UNKNOWN_TYP_IN_HEADER)


def check_trust_marks(trust_marks, results, statement_type):
    # Trust marks should only be used in Entity Configurations -> Not in V22
    if statement_type != STATEMENT_TYPE_EC:
        pass
        # add_warning(results, WARN_TRUST_MARKS_ONLY_IN_ENTITY_CONFIG)

    if not isinstance(trust_marks, list):
        add_error(results, ERR_TRUST_MARKS_MUST_BE_ARRAY)
        return

    results['tm_count'] = len(trust_marks)

    for i, trust_mark in enumerate(trust_marks):
        if not isinstance(trust_mark, dict):
            add_tm_error(results, i, ERR_TRUST_MARK_MUST_BE_DICT)
            continue

        check_trust_mark_header(results, i, trust_mark)

        # TODO disabled for SPID/CIE
        # if trust_mark['trust_mark_id_claim_name'] == 'id':
        #     add_tm_error(results, i, TRUST_MARK_DEPRECATED_ID)

        # Check for both old and new field names
        if not trust_mark['trust_mark_id']:
            add_tm_error(results, i, ERR_TRUST_MARK_MISSING_ID)

        if trust_mark['trust_mark_other_claims']:
            if 'trust_mark_other_claims' in results:
                results['trust_mark_other_claims'][i] = trust_mark['trust_mark_other_claims']
            else:
                results['trust_mark_other_claims'] = {i: trust_mark['trust_mark_other_claims']}

        # Each trust mark MUST have trust_mark field (which is a JWT)
        if not trust_mark["trust_mark"]:
            add_tm_error(results, i, ERR_TRUST_MARK_MISSING_FIELD)
            return

        if not trust_mark['trust_mark']['signature_valid']:
            add_tm_error(results, i, ERR_TRUST_MARK_SIGNATURE_INVALID)

        if trust_mark['trust_mark']['errors']:
            add_tm_error(results, i, ERR_TRANSFORMER_TRUST_MARK_ERROR)


def check_constraints(constraints, results):
    if not isinstance(constraints, dict):
        add_error(results, ERR_CONSTRAINTS_MUST_BE_OBJECT)
        return

    # Check for max_path_length constraint
    if "max_path_length" in constraints:
        max_path = constraints["max_path_length"]

        # max_path_length MUST be a non-negative integer
        if not isinstance(max_path, int) or max_path < 0:
            add_error(results, ERR_MAX_PATH_LENGTH_MUST_BE_NON_NEGATIVE)

    # Check for allowed_leaf_entity_types constraint
    if "allowed_leaf_entity_types" in constraints:
        entity_types = constraints["allowed_leaf_entity_types"]

        # allowed_leaf_entity_types MUST be an array
        if not isinstance(entity_types, list):
            add_error(results, ERR_ALLOWED_LEAF_ENTITY_TYPES_MUST_BE_ARRAY)
        else:
            # Each entity type MUST be a string
            for entity_type in entity_types:
                if not isinstance(entity_type, str):
                    add_error(results, ERR_ENTITY_TYPE_IN_ALLOWED_LEAF_MUST_BE_STRING)


def check_metadata(payload, results, statement_type):
    # For Entity Configuration, metadata is required
    if statement_type == STATEMENT_TYPE_EC and "metadata" not in payload:
        add_error(results, ERR_MISSING_METADATA_CLAIM)
        return

    # For Subordinate Statement, metadata is optional
    if statement_type == STATEMENT_TYPE_SS and "metadata" not in payload:
        if "metadata_policy" not in payload:
            add_warning(results, WARN_SUBORDINATE_MISSING_METADATA_AND_POLICY)
        return

    if "metadata" not in payload:
        return

    metadata = payload["metadata"]
    if not metadata:
        add_warning(results, WARN_EMPTY_METADATA_OBJECT)
        return

    # Check entity type
    check_entity_types(metadata, results)

    # Track entity types in metadata
    entity_types = list(metadata)
    results["metadata_entity_types"] = entity_types

    check_entity_type_metadata(metadata, results)

    results["entity_type_calc"] = get_entity_type_from_metadata(metadata)


def check_metadata_policy(metadata_policy, results):
    if not metadata_policy:
        add_warning(results, WARN_EMPTY_METADATA_POLICY_OBJECT)
        return

    for category in metadata_policy:
        if category not in ENTITY_TYPES_OIDFED:
            add_warning(results, WARN_UNKNOWN_METADATA_CATEGORY)

        # Check policy operators if present
        if metadata_policy[category]:
            check_policy_operators(metadata_policy[category], f"metadata_policy.{category}", results)


def check_policy_operators(policy_object, path, results):
    valid_operators = ["value", "add", "default", "subset_of", "one_of",
                       "super_set_of", "essential"]

    for key, value in policy_object.items():
        # Check if nested object needs recursive validation
        if isinstance(value, dict):
            check_policy_operators(value, f"{path}.{key}", results)
            continue

        # Check for unrecognized operators
        if key in valid_operators:
            # Check for "essential" operator value
            if key == "essential" and not isinstance(value, bool):
                add_error(results, ERR_ESSENTIAL_OPERATOR_MUST_BE_BOOLEAN)
        else:
            # Not a valid operator, could be a metadata field
            pass


def check_entity_types(metadata, results):

    # Check if at least one entity type is present
    entity_types = set(metadata) & ENTITY_TYPES_OIDFED

    if not entity_types:
        add_error(results, ERR_ENTITY_MUST_HAVE_KNOWN_TYPE_IN_METADATA)

    results["known_entity_types"] = entity_types


def check_entity_type_metadata(metadata, results):
    for entity_type, type_metadata in metadata.items():
        if entity_type == ENTITY_TYPE_FE:
            check_federation_entity_metadata(type_metadata, results)
        elif entity_type == ENTITY_TYPE_OPENID_RP:
            check_openid_rp_metadata(type_metadata, results)
        elif entity_type == ENTITY_TYPE_OPENID_OP:
            check_openid_provider_metadata(type_metadata, results)
        else:
            # Unknown entity type
            pass


def check_federation_entity_metadata(metadata, results):
    # Check for organization_name (recommended)
    if "organization_name" not in metadata:
        add_warning(results, WARN_MISSING_RECOMMENDED_ORGANIZATION_NAME)

    # Check if this is a Leaf Entity (RP or client)
    is_leaf_entity = False
    entity_types = results.get("metadata_entity_types", [])
    leaf_entity_types = ["openid_relying_party", "oauth_client"]
    for leaf_type in leaf_entity_types:  # TODO can be improved
        if leaf_type in entity_types:
            is_leaf_entity = True
            break

    # Check endpoints
    endpoint_keys = [
        "federation_fetch_endpoint",
        "federation_list_endpoint",
        "federation_resolve_endpoint",
        "federation_trust_mark_status_endpoint",
        "federation_trust_mark_list_endpoint",
        "federation_trust_mark_endpoint",
        "federation_historical_keys_endpoint"
    ]

    for endpoint_key in endpoint_keys:
        if endpoint_key in metadata:
            # Leaf Entities MUST NOT contain federation_fetch_endpoint and federation_list_endpoint
            if is_leaf_entity and endpoint_key in ["federation_fetch_endpoint", "federation_list_endpoint"]:
                add_error(results, ERR_LEAF_ENTITIES_MUST_NOT_CONTAIN_FETCH_ENDPOINTS)

            endpoint_url = metadata[endpoint_key]
            # Check https scheme
            if not endpoint_url.startswith("https://"):
                add_error(results, ERR_ENDPOINT_NOT_HTTPS)
            # Check for fragments
            if "#" in endpoint_url:
                add_error(results, ERR_ENDPOINT_CONTAINS_FRAGMENT)


def check_openid_rp_metadata(metadata, results):
    # Check for required client_registration_types
    if "client_registration_types" not in metadata:
        add_error(results, ERR_MISSING_CLIENT_REGISTRATION_TYPES)
    elif not isinstance(metadata["client_registration_types"], list):
        add_error(results, ERR_CLIENT_REGISTRATION_TYPES_MUST_BE_ARRAY)
    elif not metadata["client_registration_types"]:
        add_error(results, ERR_EMPTY_CLIENT_REGISTRATION_TYPES_ARRAY)


def check_openid_provider_metadata(metadata, results):
    # Check for required client_registration_types_supported
    if "client_registration_types_supported" not in metadata:
        add_error(results, ERR_EMPTY_CLIENT_REGISTRATION_TYPES_SUPPORTED_ARRAY)
    elif not isinstance(metadata["client_registration_types_supported"], list):
        add_error(results, ERR_CLIENT_REGISTRATION_TYPES_SUPPORTED_MUST_BE_ARRAY)
    elif not metadata["client_registration_types_supported"]:
        add_error(results, ERR_MISSING_CLIENT_REGISTRATION_TYPES_SUPPORTED_ARRAY)

    # Check issuer matches iss claim
    if "issuer" not in metadata:
        add_error(results, ERR_MISSING_ISSUER_IN_OPENID_PROVIDER)

    # Check federation_registration_endpoint if supports explicit registration
    if "client_registration_types_supported" in metadata and "explicit" in metadata[
        "client_registration_types_supported"]:
        if "federation_registration_endpoint" not in metadata:
            add_error(results, "Missing required 'federation_registration_endpoint' when 'explicit' registration is supported")
        elif "federation_registration_endpoint" in metadata:
            endpoint_url = metadata["federation_registration_endpoint"]

            # Check https scheme
            if not endpoint_url.startswith("https://"):
                add_error(results, ERR_FEDERATION_ENDPOINT_NOT_HTTPS)

            # Check for fragments
            if "#" in endpoint_url:
                add_error(results, ERR_FEDERATION_ENDPOINT_CONTAINS_FRAGMENT)


# Helper functions
def add_error(results, error_type):
    results['errors'].append(error_type)


def add_tm_error(results, i, error_type):
    if i in results['errors_trust_marks']:
        results['errors_trust_marks'][i].append(error_type)
    else:
        results['errors_trust_marks'][i] = [error_type]


def add_warning(results, warning_type):
    results['warnings'].append(warning_type)
