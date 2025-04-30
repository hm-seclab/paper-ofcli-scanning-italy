import base64
import copy
import json
import logging
import os
import re
from collections import deque
from datetime import timedelta, datetime
from typing import Dict, Any, Iterator, Tuple

import jwt

OPENID_FED_SPEC_URL = "https://openid.net/specs/openid-federation-1_0.html"

CIE_TA_ENTITY_ID = 'https://oidc.registry.servizicie.interno.gov.it/'
KNOWN_TRUST_ANCHORS = [CIE_TA_ENTITY_ID]
KNOWN_TRUST_MARK_CLAIM_NAMES = ['trust_mark', 'trust_mark_id']
KNOWN_TRUST_MARK_CLAIM_NAMES_WITH_DEPRECATED = ['trust_mark', 'trust_mark_id', 'id']

TRUST_MARK_JWT_TYP = 'trust-mark+jwt'
ENTITY_STATEMENT_JWT_TYP = 'entity-statement+jwt'
SIGNED_JWKS_JWT_TYP = 'jwk-set+jwt'
TRUST_MARK_DELEGATION_JWT_TYP = 'trust-mark-delegation+jwt'

STATEMENT_TYPE_ES = 'es'
STATEMENT_TYPE_EC = 'ec'
STATEMENT_TYPE_SS = 'ss'

ENTITY_TYPE_FE = 'federation_entity'
ENTITY_TYPE_OPENID_RP = 'openid_relying_party'
ENTITY_TYPE_OPENID_OP = 'openid_provider'
ENTITY_TYPE_TMI = 'trust_mark_issuer'
ENTITY_TYPES_OIDC = {ENTITY_TYPE_FE, ENTITY_TYPE_OPENID_RP, ENTITY_TYPE_OPENID_OP}

ENTITY_TYPE_OAUTH_AUTH_SERVER = 'oauth_authorization_server'
ENTITY_TYPE_OAUTH_CLIENT = 'oauth_client'
ENTITY_TYPE_OAUTH_RESOURCE = 'oauth_resource'
ENTITY_TYPES_OAUTH = {ENTITY_TYPE_OAUTH_AUTH_SERVER, ENTITY_TYPE_OAUTH_CLIENT, ENTITY_TYPE_OAUTH_RESOURCE}

ENTITY_TYPES_OIDFED = ENTITY_TYPES_OIDC | ENTITY_TYPES_OAUTH

ENTITY_ROLE_TA = 'trust_anchor'
ENTITY_ROLE_IE = 'intermediate_entity'
ENTITY_ROLE_LE = 'leaf_entity'

KNOWN_JWKS_EXTENSIONS = {'signed_jwks_uri', 'jwks_uri', 'jwks'}

JWT_LEEWAY_FINE = timedelta(seconds=10)
CPU_CORES = os.cpu_count()


def _decode_jwt_without_validation(jwt_str: str):
    header = {}
    payload = {}
    signature = ''
    errors = []

    try:
        header = jwt.get_unverified_header(jwt_str)
        if 'alg' not in header:
            errors.append(f'Error during JWT decoding without validation: No alg in header, unable to decode!')
            return header, payload, signature, errors
        else:
            alg = header['alg']

    except Exception as e:
        errors.append(f'Error during JWT decoding without validation: {str(e)}')
        return header, payload, signature, errors

    try:
        decoded_result = jwt.decode_complete(jwt_str, alg=alg, options={'verify_signature': False, "verify_exp": False})
        header = decoded_result['header']
        payload = decoded_result['payload']
        signature = base64.b64encode(decoded_result['signature']).decode('ascii')
    except Exception as e:
        errors.append(f'Error during JWT decoding without validation: {str(e)}')

    return header, payload, signature, errors


def _decode_and_verify_oidfed_jwts(subject: str, issuer: dict, include_signature=False) -> dict:
    # Decode without validation
    header, payload, _, errors = _decode_jwt_without_validation(subject)
    if errors:
        return {
            "header": header,
            "payload": payload,
            "errors": errors,
            "signature_valid": False
        }
    if not issuer:
        return {
            "header": header,
            "payload": payload,
            "errors": ['Error during JWT decoding: No issuer EC given!'],
            "signature_valid": False
        }

    # Extract key used for signing
    sig_key, errors = extract_kid_key_from_jwks_with_header(header, issuer)
    if errors:
        return {
            "header": header,
            "payload": payload,
            "errors": errors,
            "signature_valid": False
        }

    # Decode and validate signature
    header, payload, _, errors = _decode_jwt_with_validation(subject, sig_key)
    return {
        "header": header,
        "payload": payload,
        "errors": errors,
        "signature_valid": len(errors) == 0
    }


def _decode_jwt_with_validation(jwt_str: str, key_obj):
    header, payload, signature, errors = _decode_jwt_without_validation(jwt_str)
    if not errors:
        try:
            jwt.decode_complete(jwt_str, key=key_obj, alg=key_obj.algorithm_name, options={'verify_signature': True, "verify_exp": False})
        except Exception as e:
            errors.append(f'Error during JWT decoding with validation: {str(e)}')

    return header, payload, signature, errors


def _decode_and_verify_tm(trust_mark_jwt, tmis):
    result = {
        "header": {},
        "payload": {},
        "errors": [],
        "signature_valid": False
    }
    errors = []

    if not 'trust_mark' in trust_mark_jwt:
        errors.append('No "trust_mark" claim found, unable to decode or validate!')
        result['errors'] = errors
        return result

    trust_mark = trust_mark_jwt['trust_mark']

    # Decode payload without signature check to get iss
    header, payload, _, decode_errors = _decode_jwt_without_validation(trust_mark)

    if decode_errors:
        result['errors'] = decode_errors
        return result

    if not 'iss' in payload:
        errors.append(f'No issuer in TM, unable to validate signature')
        result['errors'] = errors
        return result

    iss = payload['iss']

    if not iss in tmis:
        errors.append(f'iss not part of TMIs, can not validate TM signature. Missing iss entity: {iss}')
        result['errors'] = errors
        return result

    iss_entity = tmis[iss]

    return _decode_and_verify_oidfed_jwts(trust_mark, iss_entity['entity_data']['payload'])


def _decode_and_verify_ec(ec_jwt_str: str) -> dict:
    # Decode without validation
    header, payload, _, errors = _decode_jwt_without_validation(ec_jwt_str)
    if errors:
        return {
            "header": header,
            "payload": payload,
            "errors": errors,
            "signature_valid": False
        }
    return _decode_and_verify_oidfed_jwts(ec_jwt_str, payload)


def _decode_and_verify_ss(ss_jwt_str: str, ec_iss_jwt: dict) -> dict:
    return _decode_and_verify_oidfed_jwts(ss_jwt_str, ec_iss_jwt)


def decode_es_with_meta(ec_data):
    current_entity_id, current_entity, parent_id, data_claim, issuer = ec_data

    # Decode current entity
    if issuer:
        entity_data_decoded = _decode_and_verify_ss(current_entity[data_claim], issuer)
    else:
        entity_data_decoded = _decode_and_verify_ec(current_entity[data_claim])

    sub = entity_data_decoded['payload']['sub']
    iss = entity_data_decoded['payload']['iss']

    # Build the result structure for the current entity
    return {
        "entity_id": current_entity_id,
        "parent_id": parent_id,
        "statement_type": STATEMENT_TYPE_EC if sub == iss else STATEMENT_TYPE_SS,
        "entity_type": get_entity_type_from_metadata(entity_data_decoded["payload"]["metadata"]) if 'metadata' in entity_data_decoded["payload"] else 'unknown',
        "entity_type_org": current_entity.get("entity_type", "default"),
        "request_time": current_entity.get("request_timestamp", None),
        "entity_data": entity_data_decoded,
    }


def decode_tm_with_meta(tm_jwt, tmis):
    trust_mark_result = {
        'trust_mark': {},
        'trust_mark_id': '',
        'trust_mark_id_claim_name': '',
        'trust_mark_other_claims': [{k: v} for k, v in tm_jwt.items() if k not in KNOWN_TRUST_MARK_CLAIM_NAMES_WITH_DEPRECATED],
    }

    # ID transformation
    if 'trust_mark_id' in tm_jwt:  # v42 case
        trust_mark_result['trust_mark_id'] = tm_jwt.get('trust_mark_id')
        trust_mark_result['trust_mark_id_claim_name'] = 'trust_mark_id'
    elif 'id' in tm_jwt:  # pre v42 case
        trust_mark_result['trust_mark_id'] = tm_jwt.get('id')
        trust_mark_result['trust_mark_id_claim_name'] = 'id'
    else:
        # Handled by checker module
        pass

    trust_mark_result['trust_mark'] = _decode_and_verify_tm(tm_jwt, tmis)

    return trust_mark_result


def get_ta_from_tree(oidfed_tree: Dict[str, Dict]) -> tuple[str, dict[str, dict]] | tuple[None, None]:
    for entity_id, entity_data, _, _ in traverse_tree_bfs(oidfed_tree):
        return entity_id, entity_data
    return None, None


def is_known_ta(entity_id):
    return [ta for ta in KNOWN_TRUST_ANCHORS if entity_id in ta]


def find_ec_in_tcs(tcs, entity_id):
    for tc in tcs:
        chain = tc['chain']
        for es in chain:
            if (es['entity_data']['signature_valid'] and
                    es['entity_data']['payload']['sub'] in entity_id and
                    es['entity_data']['payload']['iss'] == es['entity_data']['payload']['sub']):
                return es
    return None


def find_ec_in_list(entity_list, target_entity_id):
    for entity in entity_list:
        if entity['entity_data']['payload']['sub'] == entity['entity_data']['payload']['iss'] == target_entity_id:
            return entity
    return None


def find_ec_in_tree(oidfed_tree: Dict[str, Any], target_entity_id: str) -> Dict[str, Dict] | None:
    for entity_id, entity_data, _, _ in traverse_tree_bfs(oidfed_tree):
        if target_entity_id.rstrip('/') == entity_id.rstrip('/'):
            return entity_data
    return None


def get_tmi_ids(ta_data):
    result = set()
    for _, tmi_list in ta_data['entity_data']['payload']['trust_mark_issuers'].items():
        for tmi_id in tmi_list:
            result.add(tmi_id)

    return result


def map_ids_from_tree(tmi_id_set, oidfed_tree):
    missing = []
    result = {}

    for tmi_id in tmi_id_set:
        entity_data = find_ec_in_tree(oidfed_tree, tmi_id)
        if entity_data:
            result[tmi_id] = entity_data
        else:
            missing.append(tmi_id)

    return result, missing


def map_ids_from_list(tmi_ids, entity_list):
    missing = []
    result = {}

    for tmi_id in tmi_ids:
        entity_data = find_ec_in_list(entity_list, tmi_id)
        if entity_data:
            result[tmi_id] = entity_data
        else:
            missing.append(tmi_id)

    return result, missing


def map_ids_from_tcs(tmi_id_set, tc_list):
    missing = []
    result = {}

    for tmi_id in tmi_id_set:
        entity_data = find_ec_in_tcs(tc_list, tmi_id)
        if entity_data:
            result[tmi_id] = entity_data
        else:
            missing.append(tmi_id)

    return result, missing


def traverse_tree_bfs(oidfed_tree: Dict[str, Dict], depth=0, uniq=False) -> Iterator[Tuple[str, Dict[str, Dict], int, str]]:
    # Initialize queue with all entities from the root level
    queue = deque([(entity_id, entity_data, depth, '') for entity_id, entity_data in oidfed_tree.items()])

    seen_set = set()

    # Process entities in BFS order
    while queue:
        entity_id, entity_data, entity_depth, parent_id = queue.popleft()

        if uniq:
            if entity_id in seen_set:
                continue
            seen_set.add(entity_id)

        # Yield the tuple of url and actual entity data dictionary
        yield entity_id, entity_data, entity_depth, parent_id

        # Add subordinates to the queue if they exist
        if "subordinates" in entity_data and entity_data["subordinates"]:
            queue.extend([
                (sub_id, sub_data, entity_depth + 1, entity_id)
                for sub_id, sub_data in entity_data["subordinates"].items()
            ])


def traverse_tree_rec(oidfed_tree: Dict[str, Dict], depth=0) -> Iterator[Tuple[str, Dict[str, Dict], int]]:
    for entity_id, entity_data in oidfed_tree.items():

        # Yield the tuple of url and actual entity data dictionary
        yield entity_id, entity_data, depth

        # Recursively process subordinates if they exist
        if "subordinates" in entity_data and entity_data["subordinates"]:
            yield from traverse_tree_rec(entity_data["subordinates"], depth + 1)


def extract_kid_key_from_jwks_with_header(header: dict, token: dict):
    errors = []
    result_key = None

    if 'kid' not in header:
        errors.append(f'No kid in header, unable to extract signing key!')
        return None, errors

    if 'jwks' not in token:
        errors.append(f'No JWKs in token, unable to extract signing key!')
        return None, errors

    if 'keys' not in token['jwks']:
        errors.append(f'No keys in JWKs, unable to extract signing key!')
        return None, errors

    kid = header['kid']
    keys = token['jwks']['keys']

    for key in keys:
        if key.get('kid') == kid:
            result_key = jwt.PyJWK.from_json(json.dumps(key))
            break

    if not result_key:
        errors.append(f'No matching key with {kid} found in JWKs, unable to extract signing key!')
    return result_key, errors


def looks_like_jwk_thumbprint(kid):
    """Check if a key ID looks like it might be a thumbprint."""
    # This is a simple heuristic - thumbprints are usually base64url-encoded and have a certain length
    long_kid = len(kid) >= 27  # SHA-256 thumbprint in base64url would be about 43 chars
    base_kid = re.match(r'^[A-Za-z0-9_-]+$', kid) is not None

    return long_kid and base_kid


def setup_logging(debug=False, silent=False):
    global CPU_CORES
    # CPU_CORES = 1 if debug else CPU_CORES

    if silent:
        level = logging.ERROR
    elif debug:
        level = logging.DEBUG
    else:
        level = logging.INFO

    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s: %(message)s'
    )


def get_output_file(scan_id, output_type, file_name, file_ext):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.makedirs(os.path.join(script_dir, f'../results/{output_type}'), exist_ok=True)
    return os.path.normpath(os.path.join(script_dir, '../results/', output_type, f'{scan_id}-{file_name}.{file_ext}'))


def lists_intersect(list1, list2):
    # Convert lists to sets for efficient intersection operation
    set1 = set(list1)
    set2 = set(list2)

    # Check if intersection is non-empty
    return len(set1.intersection(set2)) > 0


def get_entity_type_from_metadata(metadata):
    broken_entity_types = ['application_type', 'client_id', 'client_registration_types', 'jwks', 'client_name', 'grant_types', 'redirect_uris', 'response_types', 'id_token_signed_response_alg', 'id_token_encrypted_response_alg',
                           'id_token_encrypted_response_enc', 'userinfo_signed_response_alg', 'userinfo_encrypted_response_alg', 'userinfo_encrypted_response_enc', 'token_endpoint_auth_method', 'subject_type']
    metadata_types = list(metadata.keys())
    if len(metadata) == 0:
        raise AssertionError('EC / ES without metadata found!')
    if len(metadata) == 1:
        return metadata_types[0]
    if len(metadata) == 2 and ENTITY_TYPE_FE in metadata:
        return [m for m in metadata_types if m != ENTITY_TYPE_FE][0]
    else:
        other_metadata = [m for m in metadata_types if m != ENTITY_TYPE_FE]
        if lists_intersect(broken_entity_types, other_metadata) and ENTITY_TYPE_FE in metadata_types:
            return 'federation_entity_broken'
        else:
            return ','.join(metadata_types)


def extract_scan_date_from_filename(filename):
    return datetime.strptime('-'.join(filename.split('-')[2:][:5]), '%Y-%m-%d-%H-%M')


def ec_equality(ec1, ec2):
    ec1_filter = copy.deepcopy(ec1)
    ec2_filter = copy.deepcopy(ec2)

    ec1_filter['entity_depth'] = None
    ec2_filter['entity_depth'] = None

    ec1_filter['request_time'] = None
    ec2_filter['request_time'] = None

    ec1_filter['parent_id'] = None
    ec2_filter['parent_id'] = None

    ec1_filter['entity_instances'] = None
    ec2_filter['entity_instances'] = None

    ec1_filter['entity_data']['payload']['iat'] = None
    ec2_filter['entity_data']['payload']['iat'] = None

    ec1_filter['entity_data']['payload']['exp'] = None
    ec2_filter['entity_data']['payload']['exp'] = None

    return ec1_filter == ec2_filter


def ss_equality(ss1, ss2):
    ss1_filter = copy.deepcopy(ss1)
    ss2_filter = copy.deepcopy(ss2)

    ss1_filter['entity_depth'] = None
    ss2_filter['entity_depth'] = None

    ss1_filter['request_time'] = None
    ss2_filter['request_time'] = None

    ss1_filter['parent_id'] = None
    ss2_filter['parent_id'] = None

    ss1_filter['entity_instances'] = None
    ss2_filter['entity_instances'] = None

    ss1_filter['entity_data']['payload']['iat'] = None
    ss2_filter['entity_data']['payload']['iat'] = None

    ss1_filter['entity_data']['payload']['exp'] = None
    ss2_filter['entity_data']['payload']['exp'] = None

    return ss1_filter == ss2_filter


def count_files_in_folder(folder_path):
    try:
        # Check if the folder exists
        if not os.path.exists(folder_path):
            raise FileNotFoundError(f"The folder '{folder_path}' does not exist.")

        # Check if the path is a directory
        if not os.path.isdir(folder_path):
            raise NotADirectoryError(f"'{folder_path}' is not a directory.")

        # List all entries in the directory
        folder_content = os.listdir(folder_path)

        # Count only files (not directories)
        return len([entry for entry in folder_content if os.path.isfile(os.path.join(folder_path, entry))])
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return -1


def unix_time_to_date(time_str):
    return datetime.fromtimestamp(int(time_str))


def split_url_label(url):
    # Find the position after the domain
    parts = url.split('/')

    if len(parts) >= 3:  # Has protocol and domain
        # Reconstruct the domain part (including protocol)
        domain_part = '/'.join(parts[:3])
        # Reconstruct the path part
        path_part = '/'.join(parts[3:])

        # Join with line break
        return f"{domain_part}/<br>{path_part}"
    else:
        # URL doesn't have the expected format, return as is
        return f"{url}<br>"


def calculate_text_offset(nodes):
    y_with_offset = []
    for i in range(len(nodes['y'])):
        # Calculate offset based on node size (larger nodes need larger offsets)
        offset = (nodes['sizes'][i] / 2)  # Half the node size plus some padding
        # y_with_offset.append((nodes['y'][i] - offset / 500)
        y_with_offset.append((nodes['y'][i] - offset / 400) - (5 / 100))

    return y_with_offset


def all_dicts_equal(dict_list):
    if not dict_list:
        return True  # Empty list case

    first_dict = dict_list[0]

    # Compare each dictionary with the first one
    return all(d == first_dict for d in dict_list)


def calculate_total_size(node_data, uniq=True):
    return len([e for e in traverse_tree_bfs(node_data, uniq=uniq)])
