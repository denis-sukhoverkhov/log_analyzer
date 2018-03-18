#!/usr/bin/env python
# -*- coding: utf-8 -*-


# log_format ui_short '$remote_addr $remote_user $http_x_real_ip [$time_local] "$request" '
#                     '$status $body_bytes_sent "$http_referer" '
#                     '"$http_user_agent" "$http_x_forwarded_for" "$http_X_REQUEST_ID" "$http_X_RB_USER" '
#                     '$request_time';
import argparse
import datetime
import gzip
import json
import logging
import os
import re
import sys
from bisect import insort, bisect_left
from collections import deque
from itertools import islice
from string import Template

config = {
    "REPORT_SIZE": 1000,
    "REPORT_DIR": "./reports",
    "LOG_DIR": "./log"
}


def load_config(path_to_file: str) -> dict:
    """
    Возвращает конфиг считывая его из файла
    :param path_to_file:
    :return:
    """
    try:
        with open(path_to_file, 'rb') as config_file:
            try:
                loaded_config = json.loads(config_file.read())
            except json.JSONDecodeError as e:
                logging.error(e)
                sys.exit(f"Broken configuration file: {path_to_file}")
    except FileNotFoundError as e:
        sys.exit(f"{e.strerror}: {path_to_file}")

    return loaded_config


def extract_date_frome_file_name(file_name):
    pattern = r"nginx-access-ui.log-(?P<date>\d{8})(.gz)?"
    match = re.match(pattern, file_name)
    if match:
        date_group = match.group(1)
        try:
            return datetime.datetime.strptime(date_group, "%Y%m%d").date()
        except ValueError as e:
            logging.error(e)
            sys.exit(f"Incorrect date format in name of file '{file_name}', it must be %Y%m%d")

    return None


def get_last_log_file(path_to_log_dir):
    """
    Возвращает путь к самому свежему файлу лога из переданной директории path_to_log_dir, фильтрует
    файлы согласно паттерну ниже.
    :param path_to_log_dir:
    :return:
    """
    files_dict = {}
    if not os.path.exists(path_to_log_dir):
        error_message = f"Directory with logs does not exist: {path_to_log_dir}"
        logging.error(error_message)
        sys.exit(error_message)
    for file_name in os.listdir(path_to_log_dir):
        files_dict[extract_date_frome_file_name(file_name)] = os.path.join(path_to_log_dir, file_name)
    date_list = list(files_dict.keys())
    date_list.sort()

    return files_dict[date_list[-1]]


def render(table_json: str, report_name: str, report_dir: str, path_to_template="./templates/report.html"):
    try:
        with open(path_to_template, "r") as f_out:
            html_template = f_out.read()

            if not os.path.exists(report_dir):
                os.makedirs(report_dir)

            path_to_report_file = os.path.join(report_dir, report_name)
            try:
                with open(path_to_report_file, "w") as f_in:
                    f_in.write(Template(html_template).safe_substitute(table_json=table_json))
            except FileNotFoundError as e:
                logging.error(e)
                sys.exit(f"Wrong path to report file: {path_to_report_file} ({e.strerror})")
    except FileNotFoundError as e:
        sys.exit(f"Wrong path to template: {path_to_template} ({e.strerror})")


def running_median_insort(seq, window_size=1000):
    """Contributed by Peter Otten"""
    seq = iter(seq)
    d = deque()
    s = []
    result = []
    for item in islice(seq, window_size):
        d.append(item)
        insort(s, item)
        result.append(s[len(d) // 2])
    m = window_size // 2
    for item in seq:
        old = d.popleft()
        d.append(item)
        del s[bisect_left(s, old)]
        insort(s, item)
        result.append(s[m])
    return result


def openfile(filename, mode='r'):
    if filename.endswith('.gz'):
        return gzip.open(filename, mode)
    else:
        return open(filename, mode)


def calculate_report(path_to_log_file, size=1000, error_threshold_perc=51):
    table = dict()

    with openfile(path_to_log_file) as f_out:
        own_num_rows = 0  # общее количество строк в логе
        error_rows = 0  # количество нераспарсенных строк
        own_num_request = 0  # общее количество распарсенных запросов
        own_sum_request_time = 0  # $request_time всех запросов
        for line in f_out:
            own_num_rows += 1
            match = re.search(r"(?P<path>\S+) HTTP\/1\.\d\".*\"(?P<request_time>.*)", line)
            if match:
                own_num_request += 1
                path = match.group(1)
                request_time = match.group(2)
                request_time = float(request_time.strip())
                own_sum_request_time += request_time

                if path in table:
                    table[path]['count'] += 1
                    table[path]['time_sum'] += request_time
                    table[path]['time_avg'].append(request_time)
                    table[path]['time_max'] = request_time if request_time > table[path]['time_max'] else table[path][
                        'time_max']
                else:
                    table[path] = {'url': path,
                                   'count': 1,
                                   'count_perc': 0,
                                   'time_avg': [request_time],
                                   'time_max': request_time,
                                   'time_med': [request_time],
                                   'time_perc': 0,
                                   'time_sum': request_time}
            else:
                error_rows += 1
    error_parse_perc = error_rows * 100 / own_num_rows if own_num_rows > 0 else 0
    logging.info(f'Percentage of errors when parsing a log: {error_parse_perc}%')
    if error_parse_perc >= error_threshold_perc:
        message = "Critical error percentage when parsing a log: {error_parse_perc}%"
        logging.error(message)
        sys.exit(message)

    table = list(table.values())
    table.sort(key=lambda el: el['time_sum'], reverse=True)
    table = table[0:size]

    round_prec = 3
    for row in table:
        len_time_list = len(row['time_avg'])
        row['time_med'] = running_median_insort(row['time_avg'], window_size=len_time_list)[-1]
        row['time_avg'] = round(sum(row['time_avg']) / len(row['time_avg']), round_prec)
        row['count_perc'] = round(row['count'] * 100 / own_num_request, round_prec)
        row['time_perc'] = round(row['time_sum'] * 100 / own_sum_request_time, round_prec)
        row['time_max'] = round(row['time_max'], round_prec)
        row['time_sum'] = round(row['time_sum'], round_prec)
    return table


def main(config: dict, args):
    loaded_config = load_config(args.config)
    merged_config = {**config, **loaded_config}

    logging.basicConfig(filename=merged_config['TS_DIR'] if 'TS_DIR' in merged_config else None,
                        level=logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s',
                        datefmt='%Y.%m.%d %H:%M:%S')
    logging.info("Program started")

    path_to_log_dir = os.path.abspath(merged_config['LOG_DIR'])
    path_to_report_dir = os.path.abspath(merged_config['REPORT_DIR'])
    log_file = get_last_log_file(path_to_log_dir)
    log_name = os.path.basename(log_file)
    date_from_log_name = extract_date_frome_file_name(log_name)
    report_name = f"report-{date_from_log_name:%Y-%m-%d}.html"

    path_to_new_report_file = os.path.join(path_to_report_dir, report_name)
    if os.path.exists(path_to_new_report_file):
        message = f"The newest report has already been generated: {path_to_new_report_file}"
        logging.info(message)
        sys.exit(message)

    # counting values for report
    table = calculate_report(log_file, size=merged_config['REPORT_SIZE'])

    # rendering html template
    render(json.dumps(table), report_name, path_to_report_dir)

    logging.info("Done!")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Log analyzer')
    parser.add_argument('--config', type=str, default='config.json', help='path to configuration file')
    args = parser.parse_args()

    main(config, args)
