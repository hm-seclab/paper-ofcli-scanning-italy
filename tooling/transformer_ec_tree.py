import argparse
import concurrent.futures
import json
import logging as log
import math
import time
from collections import Counter
from pathlib import Path

import networkx as nx
import plotly.express as px
import plotly.graph_objects as go
from tqdm import tqdm

from oidfed.commons import get_output_file, get_entity_type_from_metadata, traverse_tree_bfs, \
    ec_equality, CPU_CORES, get_ta_from_tree, setup_logging, calculate_total_size, get_tmi_ids, map_ids_from_tree, decode_tm_with_meta, decode_es_with_meta, is_known_ta, STATEMENT_TYPE_EC, map_ids_from_list, find_ec_in_list, \
    ENTITY_TYPE_OPENID_OP, ENTITY_TYPE_OPENID_RP, ENTITY_TYPE_FE, ENTITY_TYPE_TMI, ENTITY_ROLE_TA


def decode_tree(oidfed_tree):
    task_list = [[entity_id, entity_data, parent_id, 'entity_configuration', None] for entity_id, entity_data, _, parent_id in traverse_tree_bfs(oidfed_tree)]
    result_list = []

    root_task = task_list.pop(0)
    root = decode_es_with_meta(root_task)
    root['parent_id'] = None
    root_id, root_data, _, _, _ = root_task

    with concurrent.futures.ProcessPoolExecutor(max_workers=CPU_CORES) as executor:
        log.info(f'Decoding {len(task_list)} ECs')
        futures = {executor.submit(decode_es_with_meta, task): task for task in task_list}

        for future in tqdm(concurrent.futures.as_completed(futures), total=len(task_list), ncols=100):
            result_list.append(future.result())

    # Include the root in the list of all nodes
    all_nodes = [root] + result_list

    # Create a dictionary mapping entity_id to node
    entity_map = {node['entity_id']: node for node in all_nodes}

    # Build the tree structure by connecting children to parents
    for node in all_nodes:
        parent_id = node['parent_id']
        if parent_id is not None and parent_id in entity_map:
            parent = entity_map[parent_id]
            if 'subordinates' not in parent:
                parent['subordinates'] = {}
            parent['subordinates'][node['entity_id']] = node

    return {root_id: root}


def validate_tms(oidfed_tree, debug_entities):
    _, ta_data = get_ta_from_tree(oidfed_tree)

    # Get TMI IDs
    tmis_id_set = get_tmi_ids(ta_data)
    log.info(f'Found {len(tmis_id_set)} TMIs in TA EC')

    # Map IDs to entities
    tmis_dict_tree, missing_tmi_ids_tree = map_ids_from_tree(tmis_id_set, oidfed_tree)
    log.info(f'{len(missing_tmi_ids_tree)} TMIs are missing, found {len(tmis_dict_tree)}/{len(tmis_id_set)} in the tree')

    tmis_dict_debug, missing_tmi_ids_debug = map_ids_from_list(missing_tmi_ids_tree, debug_entities)
    log.info(f'{len(missing_tmi_ids_debug)} TMIs are still missing, found {len(tmis_dict_debug)}/{len(tmis_id_set)} in the debug data')

    tmis_dict = tmis_dict_tree | tmis_dict_debug

    if missing_tmi_ids_debug:
        log.warning(f'Unable to find the following TMIs in tree / debug data:')
    for missing_tmi_id in missing_tmi_ids_debug:
        log.warning(f'    {missing_tmi_id}')

    # Process TMs
    for _, entity_data, _, _ in tqdm(traverse_tree_bfs(oidfed_tree), total=calculate_total_size(oidfed_tree, uniq=False), ncols=100):
        es_data = entity_data['entity_data']['payload']
        if 'trust_marks' in es_data:
            es_data['trust_marks'] = [decode_tm_with_meta(tm, tmis_dict) for tm in es_data['trust_marks']]

    # Process debug TMs
    for entity_data in tqdm(debug_entities, ncols=100):
        es_data = entity_data['entity_data']['payload']
        if 'trust_marks' in es_data:
            es_data['trust_marks'] = [decode_tm_with_meta(tm, tmis_dict) for tm in es_data['trust_marks']]

    return oidfed_tree, debug_entities


def flatten_tree(oidfed_tree, debug_entities):
    data_lost = 0
    entity_id_set = set()
    result_list = []
    result_list_with_debug = []

    for entity_id, entity_data, entity_depth, _ in traverse_tree_bfs(oidfed_tree):
        if entity_id in entity_id_set:
            existing_data = find_ec_in_list(result_list, entity_id)
            if existing_data == entity_data:
                log.debug(f"Duplicate entity with id {entity_id} found in tree during flattening, but data are fully equal, dropping")
                continue
            elif ec_equality(existing_data, entity_data):
                log.debug(f"Duplicate entity with id {entity_id} found in tree during flattening, but data are almost equal, dropping")
                existing_data['entity_depth'].append(entity_depth)
                existing_data['entity_instances'] += 1
                continue
            else:
                data_lost += 1
                log.warning(f"Duplicate entity with id {entity_id} found in tree during flattening, but data is different, dropping, data is lost!")
                log.warning("Existing data:")
                log.warning(json.dumps(existing_data))
                log.warning("New data:")
                log.warning(json.dumps(entity_data))
        else:
            # Create a copy of entity data without subordinates
            final_entity = {k: v for k, v in entity_data.items() if k != 'subordinates'}
            final_entity['entity_depth'] = [entity_depth]
            final_entity['entity_instances'] = 1

            result_list.append(final_entity)
            entity_id_set.add(entity_id)

    if data_lost:
        log.info(f'Data was lost during flattening {data_lost} times.')
    else:
        log.info('No data loss during flattening!')

    result_list_with_debug = result_list

    if debug_entities:
        entity_id_set_with_debug = entity_id_set
        data_lost = 0
        for entity_data in debug_entities:
            entity_id = entity_data['entity_id']

            if entity_id in entity_id_set_with_debug:
                existing_data = find_ec_in_list(result_list_with_debug, entity_id)
                if existing_data == entity_data:
                    log.debug(f"Duplicate entity with id {entity_id} found in tree during flattening, but data are fully equal, dropping")
                    continue
                elif ec_equality(existing_data, entity_data):
                    log.debug(f"Duplicate entity with id {entity_id} found in tree during flattening, but data are almost equal, dropping")
                    existing_data['entity_instances'] += 1
                    continue
                else:
                    data_lost += 1
                    log.warning(f"Duplicate entity with id {entity_id} found in tree during debug flattening, but data is different, dropping, data is lost!")
                    log.warning("Existing data:")
                    log.warning(json.dumps(existing_data))
                    log.warning("New data:")
                    log.warning(json.dumps(entity_data))
            else:
                # Create a copy of entity data without subordinates
                final_entity = {k: v for k, v in entity_data.items() if k != 'subordinates'}
                final_entity['entity_instances'] = 1

                result_list_with_debug.append(final_entity)
                entity_id_set_with_debug.add(entity_id)

        if data_lost:
            log.info(f'Data was lost during debug flattening {data_lost} times.')
        else:
            log.info('No data loss during debug flattening!')

    return result_list, result_list_with_debug


def process_entity_with_cty(line):
    data = '{' + line.split('mapping: {')[1]
    return json.loads(data)


def process_debug_logs(debug_output):
    log.info('')
    log.info("# Processing debug logs")

    debug_entities = []

    debug_output_lines = debug_output.splitlines()
    debug_line_count = 0
    debug_count_other = 0
    debug_lines_other = []

    warning_line_count = 0
    warning_count_other = 0
    warning_lines_other = []

    error_line_count = 0
    error_jws = 0
    unkown_line_count = 0

    fail_timeout = 0
    fail_sub_list_endpoint = 0
    fail_sub_other = 0
    fail_sub_other_warn = 0
    fail_connect_ssl = 0
    fail_connect_dns = 0
    fail_connect_other = 0
    fail_cty = 0
    fail_non200 = 0

    for line in debug_output_lines:
        if line.startswith('debug: '):
            debug_line_count += 1
            if 'Created tree node for' in line:
                pass
            elif 'Entity has multiple metadata types' in line:
                pass
            elif 'Connection timeout to host' in line:  # appears twice, and as a warning, caught there
                pass
            elif 'Caused by ConnectTimeoutError' in line:
                fail_timeout += 1
            elif 'Could not fetch subordinates, likely a leaf entity: No federation_list_endpoint found in metadata!' in line:
                fail_sub_list_endpoint += 1
            elif 'Could not fetch subordinates' in line:
                fail_sub_other += 1
            elif 'certificate verify failed:' in line:  # appears twice, and as a warning, caught there
                pass
            elif 'Domain name not found' in line:  # appears twice, and as a warning, caught there
                pass
            elif 'Cannot connect to host' in line:
                fail_connect_other += 1
            else:
                debug_count_other += 1
                debug_lines_other.append(line)

        elif line.startswith('warning: '):
            warning_line_count += 1
            if 'Entity configuration payload is not a mapping' in line:
                fail_cty += 1
                debug_entities.append(process_entity_with_cty(line))
            elif 'Entity has multiple metadata types' in line:
                pass
            elif 'certificate verify failed:' in line:
                fail_connect_ssl += 1
            elif 'Connection timeout to host' in line:
                fail_timeout += 1
            elif '. Status code: ' in line:
                fail_non200 += 1
            elif 'Domain name not found' in line:
                fail_connect_dns += 1
            elif 'Could not parse entity configuration as JWS' in line:  # handled below
                pass
            elif 'Could not fetch subordinate' in line:
                fail_sub_other_warn += 1
            else:
                warning_count_other += 1
                warning_lines_other.append(line)

        elif line.startswith('error: '):
            error_line_count += 1
        elif line.startswith('Could not parse JWS: '):
            error_jws += 1
        else:
            unkown_line_count += 1

    log.info(f'Processed debug log lines: {len(debug_output_lines)}')
    log.info('')
    log.info(f"Debug messages:            {debug_line_count}")
    log.info(f"Warnings:                  {warning_line_count}")
    log.info(f"Errors:                    {error_line_count}")
    log.info('')
    log.info('Error types:')
    log.info('')
    log.info(f'Non 200 response errors:             {fail_non200}')
    log.info(f'Timeout errors:                      {fail_timeout}')
    log.info(f'SSL errors:                          {fail_connect_ssl}')
    log.info(f'DNS errors:                          {fail_connect_dns}')
    log.info(f'Other network errors:                {fail_connect_other}')
    log.info(f'JWKs errors:                         {error_jws}')
    log.info(f'CTY errors:                          {fail_cty}')
    log.info(f'debug: unable to fetch subs:         {fail_sub_other}')
    log.info(f'warning: unable to fetch subs:       {fail_sub_other_warn}')
    log.info(f'No subordinate list endpoint errors: {fail_sub_list_endpoint}')
    log.info(f'-------------------------------------')
    log.info(f'TOTAL network errors:                {fail_non200 + fail_timeout + fail_connect_ssl + fail_connect_dns + fail_connect_other}')
    log.info(f'TOTAL sub errors:                    {fail_sub_other + fail_sub_other_warn + fail_sub_list_endpoint}')

    log.info('')
    log.info(f'{len(debug_entities)} additional entities from debug logs!')

    result = []
    for entity in debug_entities:
        debug_entity_skeleton = {
            "entity_id": entity['sub'],
            "parent_id": 'debug_entity_parent_missing',
            "statement_type": STATEMENT_TYPE_EC,
            "entity_type": get_entity_type_from_metadata(entity["metadata"]),
            "entity_type_org": 'debug_entity_no_org_type',
            "request_time": None,
            'entity_data': {
                'header': {},
                'payload': entity,
                'errors': ['debug entity'],
                'signature_valid': False
            }
        }
        result.append(debug_entity_skeleton)

    return result


def process_tree_data(tree_data, debug_entities, scan_id):
    log.info('')
    log.info("# Processing tree topology")
    decoded_tree_data = decode_tree(tree_data)

    log.info('Validating TMs')
    decoded_tree_data, decoded_debug_entities = validate_tms(decoded_tree_data, debug_entities)

    outfile_path = get_output_file(scan_id, "tree", "tree-normal-only", "json")
    with open(outfile_path, 'w') as outfile:
        log.info('')
        log.info(f'# Writing tree data to disk')
        json.dump(decoded_tree_data, outfile, indent=4)
        log.info(f"Tree data data has been written to")
        log.info(f"    {outfile_path}")

    return decoded_tree_data, decoded_debug_entities


def process_flat_data(oidfed_tree, debug_entities, scan_id):
    log.info('')
    log.info('# Processing flat JWTs')
    decoded_flat_data, decoded_flat_data_with_debug = flatten_tree(oidfed_tree, debug_entities)
    log.info(f'Decoded and flattened data, got {len(decoded_flat_data)} different entities')

    outfile_path = get_output_file(scan_id, "flat", "flat-normal-only", "json")
    with open(outfile_path, 'w') as outfile:
        log.info('')
        log.info(f'# Writing normal flat data only to disk')
        json.dump(decoded_flat_data, outfile, indent=4)
        log.info(f'Flat data has been written to')
        log.info(f'    {outfile_path}')

    outfile_path = get_output_file(scan_id, "flat", "flat-all", "json")
    with open(outfile_path, 'w') as outfile:
        log.info('')
        log.info(f'# Writing all data with debug to disk')
        json.dump(decoded_flat_data_with_debug, outfile, indent=4)
        log.info(f"Flat + debug data has been written to")
        log.info(f"    {outfile_path}")


def process_graph_chart(decoded_tree_data, scan_id):
    log.info('')
    log.info("# Making graph chart")
    log.info("Building graph data")
    graph_data = prepare_graph_data(decoded_tree_data)

    log.info("Rendering graph chart")
    render_graph_chart(graph_data, scan_id)


def prepare_graph_data(oidfed_tree):
    graph = nx.Graph()
    # graph = nx.DiGraph()

    # Calculate strange entities
    parent_map = {}
    for entity_id, entity_data, _, parent_id in traverse_tree_bfs(oidfed_tree):
        if entity_id in parent_map:
            parent_map[entity_id].append(parent_id)
        else:
            parent_map[entity_id] = [parent_id]

    strange_entities = {k: v for k, v in parent_map.items() if len(v) > 1}

    # Create nodes and edges
    le_map = {}
    ie_weights = {}
    for entity_id, entity_data, _, parent_id in traverse_tree_bfs(oidfed_tree):

        # Skip strange entities for now
        if entity_id in strange_entities:
            continue

        # TA
        if not parent_id:
            total_size = calculate_total_size({entity_id: entity_data}, uniq=True)
            graph.add_node(entity_id, entity_type=ENTITY_ROLE_TA, size=total_size, has_subs=True)
            continue

        # IEs
        entity_type = entity_data['entity_type']
        if 'subordinates' in entity_data:
            total_size = calculate_total_size({entity_id: entity_data}, uniq=True)
            weight = scale_node_weight(total_size)
            graph.add_node(entity_id, entity_type=entity_type, size=total_size, has_subs=True)
            graph.add_edge(parent_id, entity_id, weight=weight)
            ie_weights[entity_id] = weight
            continue

        # LEs
        if parent_id in le_map:
            parent = le_map[parent_id]
            if entity_type in parent:
                parent[entity_type].append(entity_id)
            else:
                parent[entity_type] = [entity_id]
        else:
            le_map[parent_id] = {entity_type: [entity_id]}

    # LE nodes
    for parent_id, leaf_data in le_map.items():
        for leaf_type in leaf_data:
            node_id = f'agg-{parent_id}-{leaf_type}'
            total_size = len(leaf_data[leaf_type])
            weight = scale_node_weight(total_size)
            graph.add_node(node_id, entity_type=leaf_type, size=total_size, has_subs=False)
            # graph.add_edge(parent_id, node_id, my_weights=1/max((len(leaf_data[leaf_type])/100), 100))
            graph.add_edge(parent_id, node_id, weight=weight)

    # Strange LEs
    strange_parents_counter = Counter(tuple(p) for p in strange_entities.values())
    for parent_tuple, count in strange_parents_counter.items():
        node_id = f'agg-{parent_tuple}-rp'
        graph.add_node(node_id, entity_type='openid_relying_party', size=count, has_subs=False)
        ie_parent = [p for p in parent_tuple if not is_known_ta(p)][0]
        parent_weight = ie_weights[ie_parent]
        for parent_id in parent_tuple:
            if is_known_ta(parent_id):
                graph.add_edge(parent_id, node_id, weight=parent_weight * 1.5)
            else:
                graph.add_edge(parent_id, node_id, weight=parent_weight)
    return graph


def scale_node_weight(node_size):
    return min(50 + (math.sqrt(node_size)), 100)


def scale_node_size_adaptive(node_size, max_size):
    percent_size = node_size / max_size
    return min(25 + (math.sqrt(percent_size * 10000)), 100)


def render_graph_chart(graph, scan_id):
    # Define color mapping for different entity types
    color_map = {
        ENTITY_ROLE_TA: "#F5F5F5",
        ENTITY_TYPE_OPENID_OP: "#F8CECC",
        ENTITY_TYPE_OPENID_RP: "#D5E8D4",
        ENTITY_TYPE_FE: "#FFF2CC",
        ENTITY_TYPE_TMI: "#DAE8FC",
        "other": "white",
        "default": "white"
    }
    color_map_outline = {
        ENTITY_ROLE_TA: "#666666",
        ENTITY_TYPE_OPENID_OP: "#B85450",
        ENTITY_TYPE_OPENID_RP: "#82B366",
        ENTITY_TYPE_FE: "#D6B656",
        ENTITY_TYPE_TMI: "#6C8EBF",
        "other": "black",
        "default": "black"
    }

    # pos = nx.spring_layout(graph,
    #                        seed=1337,
    #                        iterations=1000,
    #                        k=0.1,
    #                        pos={TA_ENTITY_ID: (0,10)},
    #                        fixed=[TA_ENTITY_ID]
    #                        )

    pos = nx.kamada_kawai_layout(graph)

    edge_x = []
    edge_y = []

    for edge in graph.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])

    edge_trace = go.Scatter(
        x=edge_x,
        y=edge_y,
        line=dict(width=1, color='#666666'),
        opacity=1,
        mode='lines',
        showlegend=False
    )

    # Create traces for all node types
    all_traces = [edge_trace]

    # Separate nodes into regular (circles) and aggregated (boxes)
    circle_nodes = {}
    box_nodes = {}

    max_node_size = 0
    for node in graph.nodes():
        max_node_size = max(graph.nodes[node]['size'], max_node_size)

    for node in graph.nodes():

        # Get the node attributes
        node_attr = graph.nodes[node]
        entity_type = node_attr['entity_type']
        has_subs = node_attr['has_subs']
        node_size = node_attr['size']

        # Scale node size for visualization
        scaled_size = scale_node_size_adaptive(node_size, max_node_size)

        # Determine whether to add to circles or boxes
        target_dict = circle_nodes if has_subs else box_nodes

        if entity_type not in target_dict:
            target_dict[entity_type] = {'x': [], 'y': [], 'text_center': [], 'sizes': []}

        x, y = pos[node]
        target_dict[entity_type]['x'].append(x)
        target_dict[entity_type]['y'].append(y)
        target_dict[entity_type]['sizes'].append(scaled_size)

        target_dict[entity_type]['text_center'].append(f"{node_size}")

    # Add slightly larger TA circle
    ta_trace = go.Scatter(
        x=[circle_nodes[ENTITY_ROLE_TA]['x'][0]],
        y=[circle_nodes[ENTITY_ROLE_TA]['y'][0]],
        mode='markers',
        name=f"ta_circle",
        marker=dict(
            size=[circle_nodes[ENTITY_ROLE_TA]['sizes'][0] + 20],
            color=color_map[ENTITY_ROLE_TA],
            sizemode='diameter',
            line=dict(width=2, color=color_map_outline[ENTITY_ROLE_TA]),
            opacity=1,
            symbol='circle'
        )
    )
    all_traces.append(ta_trace)

    # Add circle traces
    for entity_type, nodes in circle_nodes.items():
        color = color_map.get(entity_type, color_map['default'])
        color_outline = color_map_outline.get(entity_type, color_map['default'])

        circle_trace = go.Scatter(
            x=nodes['x'],
            y=nodes['y'],
            mode='markers',
            name=f"{entity_type}",
            marker=dict(
                size=nodes['sizes'],
                color=color,
                sizemode='diameter',
                line=dict(width=2, color=color_outline),
                opacity=1,
                symbol='circle'
            )
        )
        all_traces.append(circle_trace)

    # Add circle text
    for entity_type, nodes in circle_nodes.items():
        circle_text_trace = go.Scatter(
            x=nodes['x'],
            y=[x - 0.005 for x in nodes['y']],
            mode='text',
            text=nodes['text_center'],
            textposition="middle center",
            textfont=dict(
                size=15,
                color='black'
            )
        )
        all_traces.append(circle_text_trace)

    # Add box traces
    for entity_type, nodes in box_nodes.items():
        color = color_map.get(entity_type, color_map['default'])
        color_outline = color_map_outline.get(entity_type, color_map['default'])

        box_trace = go.Scatter(
            x=nodes['x'],
            y=nodes['y'],
            mode='markers',
            name=f"{entity_type} (aggregated)",
            marker=dict(
                size=nodes['sizes'],
                color=color,
                sizemode='diameter',
                line=dict(width=2, color=color_outline),
                opacity=1,
                symbol='square'  # Use square symbol for aggregated nodes
            )
        )
        all_traces.append(box_trace)

    # Add box text
    for entity_type, nodes in box_nodes.items():
        box_text_trace = go.Scatter(
            x=nodes['x'],
            y=[x - 0.005 for x in nodes['y']],
            mode='text',
            text=nodes['text_center'],
            textposition="middle center",
            textfont=dict(
                size=15,
                color='black'
            )
        )
        all_traces.append(box_text_trace)

    # Fix for https://github.com/plotly/plotly.py/issues/3469
    fig = px.scatter(x=[0, 1, 2, 3, 4], y=[0, 1, 4, 9, 16])
    fig.write_image(get_output_file(scan_id, "visualizations", "figure-graph", "pdf"))
    time.sleep(1)

    fig = go.Figure(
        data=all_traces,
        layout=go.Layout(
            # showlegend=True,
            showlegend=False,
            hovermode='closest',
            margin=dict(b=0, l=0, r=0, t=0),
            title=scan_id,
            # legend_title="Entity Types"
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            xaxis=dict(
                showgrid=False,
                zeroline=False,
                showticklabels=False
            ),
            yaxis=dict(
                showgrid=False,
                zeroline=False,
                showticklabels=False
            )
        )
    )
    output_file = get_output_file(scan_id, "visualizations", "figure-graph", "pdf")
    log.info('')
    log.info(f'# Writing graph PDF to disk')
    fig.write_image(output_file, width=1500, height=1000)
    log.info('Graph PDF has been written to')
    log.info(f'    {output_file}')


def split_logs_and_tree(input_file):
    log.info('')
    log.info(f'# Reading input file')

    logs_content = ''
    json_content = ''
    json_started = False

    line_count = 0
    json_line_count = 0
    debug_line_count = 0

    with open(input_file, 'r') as infile:
        for line in infile:
            line_count += 1
            if json_started or line.lstrip().startswith('{'):
                json_started = True
                json_content += line
                json_line_count += 1
            else:
                logs_content += line
                debug_line_count += 1

    log.info(f'Lines:       {line_count}')
    log.info(f'Debug lines: {debug_line_count}')
    log.info(f'JSON lines:  {json_line_count}')

    return logs_content, json.loads(json_content)


def print_stats(tree):
    tac = 1
    soc = 1
    fec = 0
    fecws = 0
    lec = 0
    opc = 0
    opcws = 0
    rpc = 0
    rpcws = 0
    tmic = 0
    tmicws = 0
    otc = 0
    otcws = 0
    ots = []
    otwss = []
    tc = 1
    tmc = 0

    d0 = 1
    d1 = 0
    d2 = 0

    seen = set()

    for entity_id, entity_data, entity_depth, _ in traverse_tree_bfs(tree):
        if entity_id == 'https://oidc.registry.servizicie.interno.gov.it':
            continue
        if entity_id not in seen:
            tc += 1
            if 'trust_marks' in entity_data['entity_data']['payload']:
                tmc += len(entity_data['entity_data']['payload']['trust_marks'])
            if entity_depth == 1:
                d1 += 1
            elif entity_depth == 2:
                d2 += 1
            else:
                print('Impossible!')
            if 'subordinates' in entity_data:
                soc += 1
                if entity_data['entity_type'] == ENTITY_TYPE_OPENID_OP:
                    opcws += 1
                elif entity_data['entity_type'] == ENTITY_TYPE_OPENID_RP:
                    rpcws += 1
                elif entity_data['entity_type'] == ENTITY_TYPE_TMI:
                    tmicws += 1
                elif entity_data['entity_type'] == ENTITY_TYPE_FE:
                    fecws += 1
                else:
                    otcws += 1
                    otwss.append(entity_data['entity_type'])
            else:
                lec += 1
                if entity_data['entity_type'] == ENTITY_TYPE_OPENID_OP:
                    opc += 1
                elif entity_data['entity_type'] == ENTITY_TYPE_OPENID_RP:
                    rpc += 1
                elif entity_data['entity_type'] == ENTITY_TYPE_TMI:
                    tmic += 1
                elif entity_data['entity_type'] == ENTITY_TYPE_FE:
                    fec += 1
                else:
                    otc += 1
                    ots.append(entity_data['entity_type'])
        seen.add(entity_id)

    log.info('')
    log.info('# Entity statistics:')
    log.info(f'Entities:                                 {tc}')
    log.info(f'Entities with    subordinates (incl. TA): {soc}')
    log.info(f'Entities without subordinates (LEs):      {lec}')
    log.info(f'TAs:                                      {tac}')
    log.info(f'IEs:                                      {fecws + rpcws + opcws}')
    log.info(f'FEs with    subordinates (IEs, excl. TA): {fecws}')
    log.info(f'FEs without subordinates (pseudo IEs):    {fec}')
    log.info(f'RPs with    subordinates (IEs):           {rpcws}')
    log.info(f'RPs without subordinates:                 {rpc}')
    log.info(f'OPs with    subordinates (IEs):           {opcws}')
    log.info(f'OPs without subordinates:                 {opc}')
    log.info(f'TMIs with subordinates (IEs):             {tmicws}')
    log.info(f'TMIs without subordinates:                {tmic}')
    log.info(f'TMs:                                      {tmc}')
    if otc > 0:
        log.info(f'Other without subordinates:               {otc}')
        log.info(f'Other without subordinates types:         {', '.join(ots)}')
    if otcws > 0:
        log.info(f'Other with subordinates:                  {otcws}')
        log.info(f'Other with subordinates types:            {', '.join(otwss)}')
    log.info('')
    log.info('# Federation Hierarchy')
    log.info(f'Entities on layer 0: {d0}')
    log.info(f'Entities on layer 1: {d1}')
    log.info(f'Entities on layer 2: {d2}')


def main():
    # Set up argument parsing
    parser = argparse.ArgumentParser(description="Verify the signatures within an OpenID Federation tree produced by ofcli subtree.")
    parser.add_argument("input_file", help="Path to ofcli output file including debug logs.")
    parser.add_argument('-g', '--graph', help="Outputs the graph of the tree as PDF", action='store_true')
    parser.add_argument('-d', '--debug', help="Outputs debug information", action='store_true')

    # Parse arguments
    args = parser.parse_args()
    input_file = args.input_file
    make_graph = args.graph
    scan_id = Path(input_file).stem

    setup_logging(args.debug)

    try:
        # LOAD DATA
        log_lines, tree_data = split_logs_and_tree(input_file)

        # PROCESS DEBUG LOGS
        debug_entities = process_debug_logs(log_lines)

        # PROCESS TREE TOPOLOGY
        decoded_tree, decoded_debug_entities = process_tree_data(tree_data, debug_entities, scan_id)

        # PROCESS FLAT JWTS
        process_flat_data(decoded_tree, decoded_debug_entities, scan_id)

        # OUTPUT GRAPH
        process_graph_chart(decoded_tree, scan_id) if make_graph else None

        # STATS
        print_stats(decoded_tree)

    except FileNotFoundError:
        log.error(f"Error: {input_file} not found.")
    except json.JSONDecodeError:
        log.error(f"Error: Failed to decode JSON from {input_file}.")
    except Exception as e:
        log.error(f"An unexpected error occurred: {e}")
        exit()

    log.info("### DONE ###")


if __name__ == "__main__":
    main()
