import argparse
import concurrent.futures
import json
import logging as log
import os
from collections import Counter
from pathlib import Path

from tqdm import tqdm

from oidfed.commons import get_output_file, count_files_in_folder, CPU_CORES, setup_logging, CIE_TA_ENTITY_ID, get_tmi_ids, find_ec_in_tcs, map_ids_from_tcs, decode_tm_with_meta, decode_es_with_meta, STATEMENT_TYPE_SS


def read_tc_file(input_file):
    timestamp = None
    debug_lines = ''
    # json_content = {}
    json_content = ''
    # chain_id = 0

    json_started = False

    with open(input_file, 'r') as infile:
        for line in infile:

            # First line
            if not timestamp:
                timestamp = int(line)
                continue

            # New chain / Fix for https://github.com/dianagudu/ofcli/pull/8
            # if json_started and '}{' in line:
            #     json_content[f'chain {chain_id}'] += '}'
            #     chain_id += 1
            #     json_content[f'chain {chain_id}'] = '{'
            #     continue
            # TC
            if json_started or line.lstrip().startswith('{'):
                json_started = True
                json_content += line

            # Debug lines
            else:
                debug_lines += line

    failed_tcs = 0

    tcs = {}

    # for chain_id_name, chain_text in json_content.items():
    #     try:
    #         tcs[chain_id_name] = json.loads(chain_text)
    #     except Exception as e:
    #         failed_tcs += 1

    try:
        tcs = json.loads(json_content)
    except Exception as e:
        failed_tcs += 1

    return timestamp, debug_lines, tcs, failed_tcs


def parse_tcs(folder_path):
    file_count = count_files_in_folder(folder_path)

    log.info('')
    log.info(f'# Parsing data from folder with {file_count} input files')

    tc_list = []
    parse_fail_c = 0
    parse_fail_tc_c = 0
    parse_success_c = 0
    parse_success_tc_c = 0

    task_list = [os.path.join(folder_path, file) for file in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, file))]
    result_list = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=CPU_CORES) as executor:
        futures = {executor.submit(read_tc_file, task): task for task in task_list}

        # Process as they complete with a progress bar
        for future in tqdm(concurrent.futures.as_completed(futures), total=len(task_list), ncols=100):
            result_list.append(future.result())

    for result in result_list:
        request_time, debug_lines, tc_jwt, failed_tcs = result
        if failed_tcs > 0:
            parse_fail_tc_c += failed_tcs
        if tc_jwt:
            parse_success_c += 1
            for _, chain_obj in tc_jwt.items():
                chain_obj['request_time'] = request_time
                tc_list.append(chain_obj)
                parse_success_tc_c += 1
        else:
            parse_fail_c += 1

    log.info(f'Files parsed:  {parse_success_c}')
    log.info(f'Files dropped: {parse_fail_c}')
    log.info(f'TCs   parsed:  {parse_success_tc_c}')
    log.info(f'TCs   dropped: {parse_fail_tc_c}')
    log.info(f'TCs processed: {len(tc_list)}')

    return tc_list


def decode_tcs(tcs_list):
    with concurrent.futures.ProcessPoolExecutor(max_workers=CPU_CORES) as executor:

        ## Decode and validate ESs only
        decoded_tcs_es = []
        ec_counter = 0
        ss_counter = 0

        log.info('')
        log.info('# Decoding ECs and SSs')
        result_list = []
        futures = {executor.submit(process_ess, task): task for task in tcs_list}

        # Process as they complete with a progress bar
        for future in tqdm(concurrent.futures.as_completed(futures), total=len(tcs_list), ncols=100):
            result_list.append(future.result())

        for result, ec_c, ss_c in result_list:
            ec_counter += ec_c
            ss_counter += ss_c
            decoded_tcs_es.append(result)
        log.info(f'Decoded ESs: {ec_counter + ss_counter}')
        log.info(f'Decoded ECs: {ec_counter}')
        log.info(f'Decoded SSs: {ss_counter}')

        error_tc_c = 0
        invalid_tc_c = 0
        for tc in decoded_tcs_es:
            chain_valid = True
            chain_errors = []
            for es in tc['chain']:
                if es['entity_data']['errors']:
                    chain_errors += es['entity_data']['errors']
                if not es['entity_data']['signature_valid']:
                    chain_valid = False
            tc['chain_valid'] = chain_valid
            tc['chain_errors'] = chain_errors

            if chain_errors:
                error_tc_c += 1
            if not chain_valid:
                invalid_tc_c += 1

        log.info(f'Got {invalid_tc_c} TCs containing invalid signatures!')
        log.info(f'Got {error_tc_c} TCs containing errors!')

        log.info('')
        log.info('# Decoding TMs')
        ta_data = find_ec_in_tcs(decoded_tcs_es, CIE_TA_ENTITY_ID)
        if not ta_data:
            log.error('Unable to find TA in TC list, aborting!')
            exit()

        tmis_id_set = get_tmi_ids(ta_data)
        tmis_ec_set, missing_tmis = map_ids_from_tcs(tmis_id_set, decoded_tcs_es)

        log.info(f'Got {len(tmis_ec_set)}/{len(tmis_id_set)} different TMIs ECs')

        if missing_tmis:
            log.warning(f'Missing ones:')
            for missing_tmi in missing_tmis:
                log.warning(f'    {missing_tmi}')

        decoded_tcs_tms = []
        tm_counter = 0

        task_list = [(tc, tmis_ec_set) for tc in decoded_tcs_es]
        result_list = []

        futures = {executor.submit(process_tms, task): task for task in task_list}

        # Process as they complete with a progress bar
        for future in tqdm(concurrent.futures.as_completed(futures), total=len(task_list), ncols=100):
            result_list.append(future.result())

        for result, tm_c in result_list:
            tm_counter += tm_c
            decoded_tcs_tms.append(result)
        log.info(f'Decoded and validated {tm_counter} TMs')

    log.info(f'Decoded and validated {len(decoded_tcs_tms)} TCs')
    return decoded_tcs_tms


def process_ess(trust_chain):
    decoded_tc = []
    parent = None
    ss_counter = 0
    ec_counter = 0

    tc = trust_chain['chain']
    tc.reverse()
    for es in tc:
        sub = es['sub']
        iss = es['iss']
        if sub == iss:
            ec_counter += 1
            decoded_es = decode_es_with_meta([sub, es, iss, 'entity_statement', None])
        else:
            ss_counter += 1
            decoded_es = decode_es_with_meta([sub, es, iss, 'entity_statement', parent['entity_data']['payload']])

        decoded_es['request_time'] = trust_chain['request_time']
        decoded_tc.append(decoded_es)
        parent = decoded_es

    decoded_tc.reverse()

    trust_chain['chain'] = decoded_tc
    return trust_chain, ec_counter, ss_counter


def process_tms(tm_task):
    tc, tmi_ecs = tm_task

    decoded_tc = []
    tm_counter = 0
    for es in tc['chain']:
        if 'trust_marks' in es['entity_data']['payload']:
            es['entity_data']['payload']['trust_marks'] = [decode_tm_with_meta(tm, tmi_ecs) for tm in es['entity_data']['payload']['trust_marks']]
            tm_counter += len(es['entity_data']['payload']['trust_marks'])
        decoded_tc.append(es)
    return decoded_tc, tm_counter


def filter_flatten_tcs(tc_list):
    log.info('')
    log.info('# Filtering SSs from TCs')

    output_list = []
    seen_list = []
    drop_counter = 0
    for tc in tqdm(tc_list, ncols=100):
        for es in tc:
            if es['statement_type'] == STATEMENT_TYPE_SS:
                sub = es['entity_data']['payload']['sub']
                iss = es['entity_data']['payload']['iss']
                pair = (iss, sub)
                if pair not in seen_list:
                    output_list.append(es)
                else:
                    drop_counter += 1
                seen_list.append(pair)

    pair_counter = Counter(seen_list)
    for pair, count in pair_counter.most_common()[:-len(seen_list) - 1:-1]:
        if count == 1:
            break
        log.info(f'    Dropped {count} times: [iss: {pair[0]} -> sub: {pair[1]}]')
    log.info(f'Dropped {drop_counter} duplicate SSs')

    return output_list


def write_results(decoded_tcs, decoded_sss, scan_id):
    ### Write only SSs to disk
    log.info('')
    log.info(f'# Writing {len(decoded_sss)} SSs to disk')
    outfile_path = get_output_file(scan_id, "flat", "flat-ss", "json")
    with open(outfile_path, 'w') as outfile:
        json.dump(decoded_sss, outfile, indent=4)
        log.info(f"Flat SS data has been written to")
        log.info(f"    {outfile_path}")

    ### Write full TCs to disk
    log.info('')
    log.info(f'# Writing {len(decoded_tcs)} TCs to disk')
    outfile_path = get_output_file(scan_id, "flat", "flat-tcs", "json")
    with open(outfile_path, 'w') as outfile:
        json.dump(decoded_tcs, outfile, indent=4)
        log.info(f"Flat TC data has been written to")
        log.info(f"    {outfile_path}")


def main():
    # Set up argument parsing
    parser = argparse.ArgumentParser(description="Verify a set of ofcli trust chains.")
    parser.add_argument("input_folder", help="Path to the trust chain folder.")
    parser.add_argument('-d', '--debug', help="Outputs debug information.", action='store_true')

    # Parse arguments
    args = parser.parse_args()
    input_folder = args.input_folder
    setup_logging(args.debug)
    scan_id = Path(input_folder).stem

    try:
        # LOAD DATA
        tcs = parse_tcs(input_folder)

        # DECODE TCs
        decoded_tcs = decode_tcs(tcs)

        # FILTER SSs
        decoded_sss = filter_flatten_tcs(decoded_tcs)

        # WRITE RESULTS
        write_results(decoded_tcs, decoded_sss, scan_id)

    except Exception as e:
        log.error(f"An unexpected error occurred: {e}")

    log.info("### DONE ###")


if __name__ == "__main__":
    main()
