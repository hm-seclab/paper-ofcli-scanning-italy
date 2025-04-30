import argparse
import csv
import json
import logging as log
import os
import statistics
from collections import Counter
from datetime import datetime
from pathlib import Path

from tqdm import tqdm

from oidfed.commons import get_output_file, unix_time_to_date, extract_scan_date_from_filename, setup_logging, traverse_tree_bfs, find_ec_in_tree, STATEMENT_TYPE_EC, calculate_total_size, all_dicts_equal, ss_equality
from oidfed.validator_entity import check_entity_statement
from oidfed.validator_errors import *


def convert_to_columns(result):
    filter_errors = [error for error in result["errors"] if error not in ERROR_FILTER]
    filter_warnings = [warning for warning in result["warnings"] if warning not in WARNING_FILTER]

    conformity_status = 'conform'
    conformity_status_filter = 'conform'

    # Set final conformity status
    if result["errors"]:
        conformity_status = "errors"
    elif result["warnings"]:
        conformity_status = "warnings"

    if filter_errors:
        conformity_status_filter = "errors"
    elif filter_warnings:
        conformity_status_filter = "warnings"

    return {
        'entity_id': result['entity_id'],
        'parent_id': result['parent_id'],
        'iss': result['iss'],
        'sub': result['iss'],
        "is_self_issued": result.get("is_self_issued"),
        'statement_type': result['statement_type'],
        'entity_type': result['entity_type'],
        'entity_type_org': result['entity_type_org'],
        'entity_type_calc': result.get('entity_type_calc', 'N/A'),
        'entity_header_cty': result['entity_header_cty'],
        'metadata_entity_types': result.get("metadata_entity_types", []),
        'request_time': result['request_time'],
        'entity_depth': result.get('entity_depth', 'N/A'),
        'entity_instances': result['entity_instances'],
        'tm_count': result.get('tm_count', 0),
        'errors_trust_marks': result['errors_trust_marks'],
        'trust_mark_other_claims': result.get('trust_mark_other_claims', {}),
        'trust_mark_header_typs': result['trust_mark_header_typs'],
        "conformity_status": conformity_status,
        "conformity_status_filtered": conformity_status_filter,
        "errors_count": len(result["errors"]),
        "errors": result["errors"],
        "errors_transformer": result.get("errors_transformer", []),
        "warnings_count": len(result["warnings"]),
        "warnings": result["warnings"],
        "warnings_count_filtered": len(filter_warnings),
        "warnings_filtered": filter_warnings,
        "errors_count_filtered": len(filter_errors),
        "errors_filtered": filter_errors,
        "unexpected_claims": "; ".join(result.get("unexpected_claims", [])),
        "iat_date": datetime.strftime(unix_time_to_date(result.get("iat_time", 0)), '%Y-%m-%d %H:%M:%S'),
        "exp_date": datetime.strftime(unix_time_to_date(result.get("exp_time", 0)), '%Y-%m-%d %H:%M:%S'),
        "lifetime_days": result.get("lifetime_days"),
        "iat": result.get("iat_time"),
        "exp": result.get("exp_time"),
        "lifetime": result.get("lifetime")
    }


def collect_results_from_tree(tree):
    checks = []
    for entity_id, entity_data, entity_depth, parent_id in tqdm(traverse_tree_bfs(tree, uniq=True), total=calculate_total_size(tree, uniq=True), ncols=100, leave=False):
        checks.extend(entity_data['checks'])
    return checks


def validate_jwks_equality(tree):
    error_count = 0
    for entity_id, entity_data, entity_depth, parent_id in tqdm(traverse_tree_bfs(tree), total=calculate_total_size(tree, uniq=False), ncols=100, leave=False):

        # Skip leafs, check is handled at their superiors
        if not entity_data.get('subordinates', {}):
            continue

        for sub_id, sub_ss in entity_data['ss'].items():
            if not sub_id in entity_data['subordinates']:
                if f'{sub_id}/' in entity_data['subordinates']:
                    log.warning('Mismatch between SS and subordinates: However, the subject is listed in the iss subordinates with suffix "/"!')
                    log.warning(f'    iss: {entity_id}, sub: {sub_id}')
                    sub_id = f'{sub_id}/'
                else:
                    log.warning('Mismatch between SS and subordinates: The subject is not listed in the iss subordinates, even with suffix "/"!')
                    log.error(f'    iss: {entity_id}, sub: {sub_id}')
                    continue

            sub_ss_jwks = sub_ss['entity_data']['payload'].get('jwks', {})
            sub_ec_jwks = entity_data['subordinates'][sub_id]['ec']['entity_data']['payload'].get('jwks', {})

            if not all_dicts_equal([sub_ss_jwks, sub_ec_jwks]):
                log.warning(f'Entity has different dicts: {entity_id}')
                error_count += 1

    if error_count > 0:
        log.warning(f'Found {error_count} invalid jwks!')
    else:
        log.info(f'All EC/SS JWKs are matching!')


def validate_merged_tree(tree):
    for entity_id, entity_data, entity_depth, parent_id in tqdm(traverse_tree_bfs(tree), total=calculate_total_size(tree, uniq=False), ncols=100, leave=False):
        entity_ec = [entity_data['ec']]
        entity_ss = [v for k, v in entity_data['ss'].items()]
        entity_es = entity_ec + entity_ss

        for es in entity_es:
            # Convert to flat structure for CSV
            result = check_entity_statement(es)
            converted_result = convert_to_columns(result)
            entity_data['checks'].append(converted_result)


def validate_tree_with_tcs(data_ecs, data_tcs):
    log.info('')
    log.info('# Restructuring EC tree data')
    tree = reconstruct_tree(data_ecs)

    log.info('')
    log.info('# Adding SSs to tree')
    merge_tcs_with_tree(tree, data_tcs)

    log.info('')
    log.info('# Validating ECs and SSs')
    validate_merged_tree(tree)

    log.info('')
    log.info('# Evaluating auth, subs, and SS relations')
    evaluate_auth_sub_ss(tree)

    log.info('')
    log.info('# Collecting checker results')
    results = collect_results_from_tree(tree)

    log.info('')
    log.info('# Validating JWKS equality')
    validate_jwks_equality(tree)

    return results


def evaluate_auth_sub_ss(tree):
    for entity_id, entity_data, entity_depth, parent_id in tqdm(traverse_tree_bfs(tree), total=calculate_total_size(tree, uniq=False), ncols=100, leave=False):

        payload = entity_data['ec']['entity_data']['payload']

        # Calculate subordinates that do not list this entity in their authority hints
        # + auth without subs
        subordinates = entity_data.get('subordinates', [])
        if subordinates:
            for sub_id, sub_data in subordinates.items():
                sub_data['parents'] = sub_data.get('parents', []) + [entity_id]
            entity_data['own_sub_without_auth'] = set([sub_id for sub_id, sub_data in subordinates.items() if
                                                       not 'authority_hints' in sub_data['ec']['entity_data']['payload'] or
                                                       not sub_data['ec']['entity_data']['payload']['authority_hints'] or
                                                       not entity_id in sub_data['ec']['entity_data']['payload']['authority_hints']])

        # Entities without authority hints (TA) do not need further checking
        authority_hints = payload.get('authority_hints', [])
        if not authority_hints:
            continue

        entity_data['auth_without_ss'] = set(authority_hints) - set(entity_data['ss'])

    # Calculate auth_without_sub_parent
    for entity_id, entity_data, entity_depth, parent_id in tqdm(traverse_tree_bfs(tree), total=calculate_total_size(tree, uniq=False), ncols=100, leave=False):
        payload = entity_data['ec']['entity_data']['payload']
        authority_hints = payload.get('authority_hints', [])

        if not authority_hints:
            continue

        entity_data['auth_without_sub_parent'] = set(authority_hints) - set(entity_data.get('parents', []))



def merge_tcs_with_tree(tree, data_tcs):
    iss_cache = {}
    duplicates = []

    for tc in tqdm(data_tcs, ncols=100, leave=False):
        for es in tc:
            if es['statement_type'] == STATEMENT_TYPE_EC:
                continue

            sub = es['entity_data']['payload']['sub']
            iss = es['entity_data']['payload']['iss']

            if iss in iss_cache:
                iss_entity = iss_cache[iss]
            else:
                iss_entity = find_ec_in_tree(tree, iss)
                iss_cache[iss] = iss_entity

            if sub in iss_entity['ss']:
                if ss_equality(es, iss_entity['ss'][sub]):
                    continue
                else:
                    duplicates.append(es)
                    log.error(f"Different SS for same sub retrieved: iss: {iss} / sub: {sub}")
            else:
                iss_entity['ss'][sub] = es
    if duplicates:
        log.warning(f'Duplicate SSs: {[x['entity_id'] for x in duplicates]}')


def reconstruct_tree(data_ecs):
    tree = {}
    entity_cache = {}

    for entity_id, entity_data, entity_depth, parent_id in tqdm(traverse_tree_bfs(data_ecs), total=calculate_total_size(data_ecs, uniq=False), ncols=100, leave=False):
        node = {
            'ec': entity_data,
            'ss': {},
            'checks': [],
            'subordinates': {},
        }

        if not parent_id:  # TA
            tree[entity_id] = node
            entity_cache[entity_id] = node
            continue

        if parent_id in entity_cache:
            parent_entity = entity_cache[parent_id]
        else:
            parent_entity = find_ec_in_tree(tree, parent_id)
            entity_cache[parent_id] = parent_entity

        parent_entity['subordinates'][entity_id] = node

    return tree


def validate_tree(oidfed_tree):
    # Check each entity statement

    results = []

    for entity_id, entity_data, _, _ in traverse_tree_bfs(oidfed_tree, uniq=True):
        result = check_entity_statement(entity_data)

        # Convert to flat structure for CSV
        converted_result = convert_to_columns(result)
        results.append(converted_result)

    return results


def load_data(file_path_ecs, file_path_tcs):
    log.info('')
    log.info(f'# Parsing data from file:')
    log.info(f'    {file_path_ecs}')
    data_ecs = None
    data_tcs = None
    with open(file_path_ecs, 'r') as file:
        data_ecs = json.load(file)
        log.info(f'Loaded EC data')

    if file_path_tcs:
        log.info('')
        log.info(f'# Parsing data from file:')
        log.info(f'    {file_path_tcs}')
        with open(file_path_tcs, 'r') as file:
            data_tcs = json.load(file)
            log.info(f'Loaded TC data')
    else:
        log.info(f'Loaded TC data (skipped)')

    return data_ecs, data_tcs


def write_results(results, scan_id):
    # Generate output file naming
    output_file = get_output_file(scan_id, "conformity", "conformity_report", "csv")
    fieldnames = results[0].keys()

    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    log.info('')
    log.info(f"Report written to")
    log.info(f"    {output_file}")


ERROR_FILTER = [
    ERR_AUTHORITY_HINTS_NOT_ALLOWED_IN_SUBORDINATE,
    ERR_CONSTRAINTS_CLAIM_NOT_ALLOWED_IN_ENTITY_CONFIG,
    ERR_LEAF_ENTITIES_MUST_NOT_CONTAIN_FETCH_ENDPOINTS
]
WARNING_FILTER = [
    WARN_ENTITY_STATEMENT_LONG_LIVED,
    WARN_ENTITY_STATEMENT_SHORT_LIVED,
    WARN_ENTITY_STATEMENT_ZERO_IAT_EXP,
    WARN_UNABLE_TO_VALIDATE_LIFETIME,
    WARN_TRUST_MARKS_ONLY_IN_ENTITY_CONFIG,
    WARN_SUBORDINATE_MISSING_METADATA_AND_POLICY,
]


def print_results(results, scan_id, silent):
    # Summary statistics

    total_count = len(results)
    entities_valid = [entity for entity in results if len(entity['warnings']) == 0 and len(entity['errors']) == 0]
    entities_with_both = [entity for entity in results if len(entity['warnings']) > 0 and len(entity['errors']) > 0]
    entities_with_either = [entity for entity in results if len(entity['warnings']) > 0 or len(entity['errors']) > 0]
    entities_with_only_errors = [entity for entity in results if len(entity['warnings']) == 0 and len(entity['errors']) > 0]
    entities_with_errors = [entity for entity in results if len(entity['errors']) > 0]
    entities_with_only_warnings = [entity for entity in results if len(entity['warnings']) > 0 and len(entity['errors']) == 0]

    valid_count = len(entities_valid)
    both_count = len(entities_with_both)
    either_count = len(entities_with_either)
    only_error_count = len(entities_with_only_errors)
    error_count = len(entities_with_errors)
    only_warning_count = len(entities_with_only_warnings)

    filter_entities_valid = [entity for entity in results if len(entity['warnings_filtered']) == 0 and len(entity['errors_filtered']) == 0]
    filter_entities_with_both = [entity for entity in results if len(entity['warnings_filtered']) > 0 and len(entity['errors_filtered']) > 0]
    filter_entities_with_either = [entity for entity in results if len(entity['warnings_filtered']) > 0 or len(entity['errors_filtered']) > 0]
    filter_entities_with_only_errors = [entity for entity in results if len(entity['warnings_filtered']) == 0 and len(entity['errors_filtered']) > 0]
    filter_entities_with_errors = [entity for entity in results if len(entity['errors_filtered']) > 0]
    filter_entities_with_only_warnings = [entity for entity in results if len(entity['warnings_filtered']) > 0 and len(entity['errors_filtered']) == 0]

    filter_valid_count = len(filter_entities_valid)
    filter_both_count = len(filter_entities_with_both)
    filter_either_count = len(filter_entities_with_either)
    filter_only_error_count = len(filter_entities_with_only_errors)
    filter_error_count = len(filter_entities_with_errors)
    filter_only_warning_count = len(filter_entities_with_only_warnings)

    if silent:
        # scan_id,total,error,warn,valid,error_rel,warn_rel,valid_rel,filter_error,filter_warn,filter_valid,filter_error_rel,filter_warn_rel,filter_valid_rel
        print(f'{scan_id},{total_count},{error_count},{only_warning_count},{valid_count},{(error_count / total_count):.2f},{(only_warning_count / total_count):.2f},{(valid_count / total_count):.2f},'
              f'{filter_error_count},{filter_only_warning_count},{filter_valid_count},{(filter_error_count / total_count):.2f},{(filter_only_warning_count / total_count):.2f},{(filter_valid_count / total_count):.2f}')
        exit()

    log.info('')
    log.info(f"# Entity validation summary:")
    log.info(f"Total:                  {total_count}")
    log.info(f" with errors only:      {only_error_count} ({only_error_count / total_count * 100:.1f}%)")
    log.info(f" with both:             {both_count} ({both_count / total_count * 100:.1f}%)")
    log.info(f" with either:           {either_count} ({either_count / total_count * 100:.1f}%)")
    log.info('-------------------------')
    log.info(f" valid:                 {valid_count} ({valid_count / total_count * 100:.1f}%)")
    log.info(f" with warnings:         {only_warning_count} ({only_warning_count / total_count * 100:.1f}%)")
    log.info(f" with errors:           {error_count} ({error_count / total_count * 100:.1f}%)")
    log.info('')
    log.info(f"# Entity validation summary with filters:")
    log.info(f" Warning filter:      {WARNING_FILTER}")
    log.info(f" Error filter:        {ERROR_FILTER}")
    log.info(f" with errors only:    {filter_only_error_count} ({filter_only_error_count / total_count * 100:.1f}%)")
    log.info(f" with both:           {filter_both_count} ({filter_both_count / total_count * 100:.1f}%)")
    log.info(f" with either:         {filter_either_count} ({filter_either_count / total_count * 100:.1f}%)")
    log.info('-------------------------')
    log.info(f" valid:               {filter_valid_count} ({filter_valid_count / total_count * 100:.1f}%)")
    log.info(f" with warnings:       {filter_only_warning_count} ({filter_only_warning_count / total_count * 100:.1f}%)")
    log.info(f" with errors:         {filter_error_count} ({filter_error_count / total_count * 100:.1f}%)")

    # Report on lifetime statistics
    lifetimes = [r.get("lifetime_days") for r in results]

    avg_lifetime = sum(lifetimes) / len(lifetimes)
    med_lifetime = statistics.median(lifetimes)
    max_lifetime = max(lifetimes)
    min_lifetime = min(lifetimes)
    log.info(f"")
    log.info(f"# Lifetimes:")
    log.info(f" Minimum: {min_lifetime:.1f} days")
    log.info(f" Median:  {med_lifetime:.1f} days")
    log.info(f" Average: {avg_lifetime:.1f} days")
    log.info(f" Maximum: {max_lifetime:.1f} days")


def assess_key_reuse(oidfed_tree):
    total_keys = 0
    total_keys_uniq_to_entities = 0
    key_list = []
    key_entities_map = {}  # Dictionary to track which entities use each key

    for entity_id, entity_data, _, _ in traverse_tree_bfs(oidfed_tree, uniq=True):

        entity_keys = entity_data['entity_data']['payload']['jwks'].get('keys', [])
        total_keys += len(entity_keys)
        entity_kids = set([x['kid'] for x in entity_keys])
        total_keys_uniq_to_entities += len(entity_kids)

        unique_entity_keys = []

        for kid in entity_kids:
            matching_key = [x for x in entity_keys if x['kid'] == kid][0]

            # Flatten lists in x5c claim
            if 'x5c' in matching_key:
                matching_key['x5c'] = matching_key['x5c'][0]

            frozen_key = frozenset(matching_key.items())
            unique_entity_keys.append(frozen_key)

            # Track which entity uses this key
            if frozen_key not in key_entities_map:
                key_entities_map[frozen_key] = []
            key_entities_map[frozen_key].append(entity_id)

        key_list += unique_entity_keys

    counter = Counter(key_list)
    result = []
    result_uniq_ids = set()
    uniq_keys = 0
    for items, count in counter.items():
        if count == 1:
            uniq_keys += 1
            result_uniq_ids.update(key_entities_map[items])
            continue

        # Convert frozenset back to dict and add count and entity IDs
        dict_with_count = dict(items)
        dict_with_count['count'] = count
        dict_with_count['entity_ids'] = key_entities_map[items]
        result.append(dict_with_count)

    result.sort(key=lambda x: x['count'])
    for item in result:
        count = item.pop('count')  # Remove and get the count
        entity_ids = item.pop('entity_ids')  # Remove and get the entity IDs
        log.info(f"This key: {item}")
        log.info(f"... is used {count} times")
        log.info(f"... by the following entities: {entity_ids if len(entity_ids) < 5 else list(entity_ids[:5]) + ['truncated...']}")

    log.info('')
    log.info(f'Total keys:                  {total_keys}')
    log.info(f'Unique keys (entity level):  {total_keys_uniq_to_entities}')
    log.info(f'Unique keys (globally):      {uniq_keys}')
    log.info(f'Reused keys (globally):      {len(result)}')
    log.info(f'Distinct keys (globally):    {uniq_keys + len(result)}')
    log.info(f'Unique key IDs (globally):   {len(result_uniq_ids)}')


def main():
    # Set up argument parsing
    parser = argparse.ArgumentParser(description="Verify OpenID Federation entity statements and trustchains according to the spec.")
    parser.add_argument("input_ecs", help="Path to JSON containing decoded entity statements.")
    parser.add_argument('-t', '--input_tcs', help="Path to JSON containing decoded flat trust chains.")
    parser.add_argument('-d', '--debug', help="Outputs debug information.", action='store_true')
    parser.add_argument("-s", "--silent", help="Silent, output stats only", action='store_true')

    # Parse arguments
    args = parser.parse_args()
    input_ecs = args.input_ecs
    input_tcs = args.input_tcs
    silent = args.silent
    setup_logging(debug=args.debug, silent=silent)
    scan_id = Path(input_ecs).stem

    # Extract scan date from filename
    scan_date = extract_scan_date_from_filename(os.path.basename(input_ecs))
    log.info(f"Detected scan date: {scan_date}, {(datetime.now() - scan_date).days} days ago")

    try:
        # LOAD DATA
        data_ecs, data_tcs = load_data(input_ecs, input_tcs)

        # VALIDATE DATA
        if data_tcs:
            result = validate_tree_with_tcs(data_ecs, data_tcs)
        else:
            result = validate_tree(data_ecs)

        # WRITE RESULTS
        write_results(result, scan_id)

        # PRINT RESULTS
        print_results(result, scan_id, silent)

        # ASSESS KEY REUSE
        assess_key_reuse(data_ecs)

    except Exception as e:
        log.error(f"An unexpected error occurred: {e}")
        log.info(f'Data from file:')
        log.info(f'    {input_ecs}')

    log.info("### DONE ###")


if __name__ == "__main__":
    main()
