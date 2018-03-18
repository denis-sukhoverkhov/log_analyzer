import datetime
import gzip
import json
import logging
import shutil
import unittest

import os
from log_analyzer import load_config, get_last_log_file, render, calculate_report, openfile, \
    extract_date_frome_file_name

logging.disable(logging.CRITICAL)


class TestLogAnalyzer(unittest.TestCase):

    def setUp(self):
        super(TestLogAnalyzer, self).setUp()

        self.abs_path = os.getcwd()
        self.path_to_temp = os.path.join(self.abs_path, 'tests', 'temp')

        if os.path.exists(self.path_to_temp):
            shutil.rmtree(self.path_to_temp)

        os.makedirs(self.path_to_temp)

    def tearDown(self):
        shutil.rmtree(self.path_to_temp)

    def _generate_plain_sample(self, file_name="nginx-access-ui.log-20170630"):
        content = """1.196.116.32 -  - [29/Jun/2017:03:50:22 +0300] "GET /api/v2/banner/25019354 HTTP/1.1" 200 927 "-" "Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5" "-" "1498697422-2190034393-4708-9752759" "dc7161be3" 0.390
1.99.174.176 3b81f63526fa8  - [29/Jun/2017:03:50:22 +0300] "GET /api/1/photogenic_banners/list/?server_name=WIN7RB4 HTTP/1.1" 200 12 "-" "Python-urllib/2.7" "-" "1498697422-32900793-4708-9752770" "-" 0.133
1.169.137.128 -  - [29/Jun/2017:03:50:22 +0300] "GET /api/v2/banner/16852664 HTTP/1.1" 200 19415 "-" "Slotovod" "-" "1498697422-2118016444-4708-9752769" "712e90144abee9" 0.199
1.199.4.96 -  - [29/Jun/2017:03:50:22 +0300] "GET /api/v2/slot/4705/groups HTTP/1.1" 200 2613 "-" "Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5" "-" "1498697422-3800516057-4708-9752745" "2a828197ae235b0b3cb" 0.704
1.168.65.96 -  - [29/Jun/2017:03:50:22 +0300] "GET /api/v2/internal/banner/24294027/info HTTP/1.1" 200 407 "-" "-" "-" "1498697422-2539198130-4709-9928846" "89f7f1be37d" 0.146
1.169.137.128 -  - [29/Jun/2017:03:50:22 +0300] "GET /api/v2/group/1769230/banners HTTP/1.1" 200 1020 "-" "Configovod" "-" "1498697422-2118016444-4708-9752747" "712e90144abee9" 0.628
1.194.135.240 -  - [29/Jun/2017:03:50:22 +0300] "GET /api/v2/group/7786679/statistic/sites/?date_type=day&date_from=2017-06-28&date_to=2017-06-28 HTTP/1.1" 200 22 "-" "python-requests/2.13.0" "-" "1498697422-3979856266-4708-9752772" "8a7741a54297568b" 0.067
1.169.137.128 -  - [29/Jun/2017:03:50:22 +0300] "GET /api/v2/banner/1717161 HTTP/1.1" 200 2116 "-" "Slotovod" "-" "1498697422-2118016444-4708-9752771" "712e90144abee9" 0.138
1.166.85.48 -  - [29/Jun/2017:03:50:22 +0300] "GET /export/appinstall_raw/2017-06-29/ HTTP/1.0" 200 28358 "-" "Mozilla/5.0 (Windows; U; Windows NT 6.0; ru; rv:1.9.0.12) Gecko/2009070611 Firefox/3.0.12 (.NET CLR 3.5.30729)" "-" "-" "-" 0.003
1.199.4.96 -  - [29/Jun/2017:03:50:22 +0300] "GET /api/v2/slot/4822/groups HTTP/1.1" 200 22 "-" "Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5" "-" "1498697422-3800516057-4708-9752773" "2a828197ae235b0b3cb" 0.157
1.196.116.32 -  - [29/Jun/2017:03:50:22 +0300] "GET /api/v2/banner/24987703 HTTP/1.1" 200 883 "-" "Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5" "-" "1498697422-2190034393-4708-9752753" "dc7161be3" 0.726
1.166.85.48 -  - [29/Jun/2017:03:50:22 +0300] "GET /export/appinstall_raw/2017-06-30/ HTTP/1.0" 404 162 "-" "Mozilla/5.0 (Windows; U; Windows NT 6.0; ru; rv:1.9.0.12) Gecko/2009070611 Firefox/3.0.12 (.NET CLR 3.5.30729)" "-" "-" "-" 0.001
1.196.116.32 -  - [29/Jun/2017:03:50:22 +0300] "GET /api/v2/banner/25020545 HTTP/1.1" 200 969 "-" "Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5" "-" "1498697422-2190034393-4708-9752761" "dc7161be3" 0.738
1.169.137.128 -  - [29/Jun/2017:03:50:23 +0300] "GET /api/v2/banner/7763463 HTTP/1.1" 200 1018 "-" "Configovod" "-" "1498697422-2118016444-4708-9752774" "712e90144abee9" 0.181
1.169.137.128 -  - [29/Jun/2017:03:50:23 +0300] "GET /api/v2/banner/16168711 HTTP/1.1" 200 16478 "-" "Slotovod" "-" "1498697422-2118016444-4708-9752775" "712e90144abee9" 0.190
1.196.116.32 -  - [29/Jun/2017:03:50:23 +0300] "GET /api/v2/banner/25023278 HTTP/1.1" 200 924 "-" "Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5" "-" "1498697422-2190034393-4708-9752762" "dc7161be3" 0.841
1.194.135.240 -  - [29/Jun/2017:03:50:23 +0300] "GET /api/v2/group/7786682/statistic/sites/?date_type=day&date_from=2017-06-28&date_to=2017-06-28 HTTP/1.1" 200 22 "-" "python-requests/2.13.0" "-" "1498697423-3979856266-4708-9752778" "8a7741a54297568b" 0.068
1.196.116.32 -  - [29/Jun/2017:03:50:23 +0300] "GET /api/v2/banner/25013431 HTTP/1.1" 200 948 "-" "Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5" "-" "1498697422-2190034393-4708-9752758" "dc7161be3" 0.917
1.168.65.96 -  - [29/Jun/2017:03:50:23 +0300] "GET /api/v2/internal/banner/24288647/info HTTP/1.1" 200 351 "-" "-" "-" "1498697423-2539198130-4708-9752780" "89f7f1be37d" 0.072
1.169.137.128 -  - [29/Jun/2017:03:50:23 +0300] "GET /api/v2/banner/21456892 HTTP/1.1" 200 70795 "-" "Slotovod" "-" "1498697423-2118016444-4708-9752779" "712e90144abee9" 0.158
1.168.65.96 -  - [29/Jun/2017:03:50:23 +0300] "GET /api/v2/internal/banner/24197629/info HTTP/1.1" 200 293 "-" "-" "-" "1498697423-2539198130-4708-9752783" "89f7f1be37d" 0.058
1.194.135.240 -  - [29/Jun/2017:03:50:23 +0300] "GET /api/v2/group/7786683/statistic/sites/?date_type=day&date_from=2017-06-28&date_to=2017-06-28 HTTP/1.1" 200 22 "-" "python-requests/2.13.0" "-" "1498697423-3979856266-4708-9752782" "8a7741a54297568b" 0.061
1.169.137.128 -  - [29/Jun/2017:03:50:23 +0300] "GET /api/v2/banner/16803530 HTTP/1.1" 200 6766 "-" "Slotovod" "-" "1498697423-2118016444-4708-9752781" "712e90144abee9" 0.156
1.196.116.32 -  - [29/Jun/2017:03:50:23 +0300] "GET /api/v2/banner/24913311 HTTP/1.1" 200 897 "-" "Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5" "-" "1498697422-2190034393-4708-9752748" "dc7161be3" 1.243
1.196.116.32 -  - [29/Jun/2017:03:50:23 +0300] "GET /api/v2/banner/25019908 HTTP/1.1" 200 989 "-" "Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5" "-" "1498697422-2190034393-4708-9752760" "dc7161be3" 1.321
1.196.116.32 -  - [29/Jun/2017:03:50:23 +0300] "GET /api/v2/banner/24998073 HTTP/1.1" 200 983 "-" "Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5" "-" "1498697422-2190034393-4708-9752755" "dc7161be3" 1.403
1.194.135.240 -  - [29/Jun/2017:03:50:23 +0300] "GET /api/v2/group/7786984/statistic/sites/?date_type=day&date_from=2017-06-28&date_to=2017-06-28 HTTP/1.1" 200 110 "-" "python-requests/2.13.0" "-" "1498697423-3979856266-4708-9752784" "8a7741a54297568b" 0.056
1.169.137.128 -  - [29/Jun/2017:03:50:23 +0300] "GET /api/v2/group/1823183/banners HTTP/1.1" 200 1002 "-" "Configovod" "-" "1498697423-2118016444-4708-9752777" "712e90144abee9" 0.680
1.196.116.32 -  - [29/Jun/2017:03:50:23 +0300] "GET /api/v2/banner/25047606 HTTP/1.1" 200 959 "-" "Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5" "-" "1498697422-2190034393-4708-9752766" "dc7161be3" 1.490
1.195.208.16 -  - [29/Jun/2017:03:50:23 +0300] "GET /api/v2/test/auth/ HTTP/1.0" 401 55 "https://rb.mail.ru/api/v2/test/auth/" "MR HTTP Monitor" "-" "1498697423-1957913694-4708-9752786" "-" 0.003
1.195.208.16 -  - [29/Jun/2017:03:50:23 +0300] "GET /accounts/login/ HTTP/1.0" 200 9982 "https://rb.mail.ru/accounts/login/" "MR HTTP Monitor" "-" "1498697423-1957913694-4708-9752785" "-" 0.035
1.195.208.16 -  - [29/Jun/2017:03:50:23 +0300] "POST /api/v2/target/12988/list?status=1 HTTP/1.0" 200 2 "https://rb.mail.ru/api/v2/target/12988/list?status=1" "MR HTTP Monitor" "-" "1498697423-1957913694-4708-9752787" "-" 0.003
1.141.250.208 -  - [29/Jun/2017:03:50:23 +0300] "GET /export/appinstall_raw/2017-06-29/ HTTP/1.0" 200 28358 "-" "Mozilla/5.0 (Windows; U; Windows NT 6.0; ru; rv:1.9.0.12) Gecko/2009070611 Firefox/3.0.12 (.NET CLR 3.5.30729)" "-" "-" "-" 0.002
1.141.250.208 -  - [29/Jun/2017:03:50:23 +0300] "GET /export/appinstall_raw/2017-06-30/ HTTP/1.0" 404 162 "-" "Mozilla/5.0 (Windows; U; Windows NT 6.0; ru; rv:1.9.0.12) Gecko/2009070611 Firefox/3.0.12 (.NET CLR 3.5.30729)" "-" "-" "-" 0.001
1.169.137.128 -  - [29/Jun/2017:03:50:23 +0300] "GET /api/v2/banner/7957213 HTTP/1.1" 200 1000 "-" "Configovod" "-" "1498697423-2118016444-4708-9752789" "712e90144abee9" 0.145
1.196.116.32 -  - [29/Jun/2017:03:50:23 +0300] "GET /api/v2/banner/25032604 HTTP/1.1" 200 919 "-" "Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5" "-" "1498697422-2190034393-4708-9752763" "dc7161be3" 1.665
1.200.76.128 f032b48fb33e1e692  - [29/Jun/2017:03:50:23 +0300] "GET /api/1/banners/?campaign=7789704 HTTP/1.1" 200 604049 "-" "-" "-" "1498697421-4102637017-4708-9752733" "-" 2.577
1.196.116.32 -  - [29/Jun/2017:03:50:23 +0300] "GET /api/v2/banner/25040266 HTTP/1.1" 200 984 "-" "Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5" "-" "1498697422-2190034393-4708-9752765" "dc7161be3" 1.680
1.168.65.96 -  - [29/Jun/2017:03:50:23 +0300] "GET /api/v2/internal/banner/24273184/info HTTP/1.1" 200 396 "-" "-" "-" "1498697423-2539198130-4707-9827576" "89f7f1be37d" 0.063
1.194.135.240 -  - [29/Jun/2017:03:50:23 +0300] "GET /api/v2/group/7808057/statistic/sites/?date_type=day&date_from=2017-06-28&date_to=2017-06-28 HTTP/1.1" 200 22 "-" "python-requests/2.13.0" "-" "1498697423-3979856266-4708-9752792" "8a7741a54297568b" 0.063
1.168.229.112 545a7b821307935d  - [29/Jun/2017:03:50:24 +0300] "GET /agency/banners_stats/?date1=26-06-2017&date2=28-06-2017&date_type=day&do=1&rt=campaign&oi=5370438&as_json=1 HTTP/1.1" 200 316 "-" "python-requests/2.13.0" "-" "1498697417-743364018-4708-9752674" "-" 6.828
1.199.168.112 2a828197ae235b0b3cb  - [29/Jun/2017:03:50:24 +0300] "GET /api/1/banners/?campaign=1236490 HTTP/1.1" 200 13945 "-" "Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5" "-" "1498697423-2760328665-4708-9752788" "-" 0.314
1.200.76.128 f032b48fb33e1e692  - [29/Jun/2017:03:50:24 +0300] "GET /api/1/campaigns/?id=7789709 HTTP/1.1" 200 608 "-" "-" "-" "1498697423-4102637017-4708-9752791" "-" 0.146"""
        path_to_file = os.path.join(self.path_to_temp, file_name)
        with open(path_to_file, "w") as file:
            file.write(content)

        return path_to_file

    def _generate_gz_sample(self, file_name="nginx-access-ui.log-20170630", is_remove_plain=False):
        path_to_plain_file = self._generate_plain_sample(file_name)
        patrh_to_gz_file = f'{path_to_plain_file}.gz'

        with open(path_to_plain_file, 'rb') as f_in:
            with gzip.open(patrh_to_gz_file, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)

        if is_remove_plain:
            os.remove(path_to_plain_file)

        return patrh_to_gz_file

    def _generate_config_file(self, file_name="config.json", config=None):

        if config is None:
            config = {
                "REPORT_SIZE": 1000,
                "REPORT_DIR": "./reports",
                "LOG_DIR": "./log"
            }
        path_to_config_file = os.path.join(self.path_to_temp, file_name)

        with open(path_to_config_file, 'w') as f_out:
            f_out.write(json.dumps(config))

        return path_to_config_file

    def _generate_table_json(self, count_rows=10):

        table = []
        for number_row in range(0, count_rows):
            table.append({'url': '/api/v2/internal/html5/phantomjs/queue/?wait=1m',
                          'count': 2767,
                          'count_perc': 0.106,
                          'time_avg': 62.995,
                          'time_max': 9843.569,
                          'time_med': 60.073,
                          'time_perc': 9.043,
                          'time_sum': 174306.352})

        return json.dumps(table)

    def test_load_normal_config(self):
        path_to_config_file = self._generate_config_file()

        config = load_config(path_to_config_file)
        self.assertIsInstance(config, dict)

    def test_load_does_not_exist_config(self):
        with self.assertRaises(SystemExit) as exc:
            load_config("some_wrong_path_to_config.json")
        self.assertIsInstance(exc.exception, SystemExit)

    def test_load_broken_json_config(self):
        path_to_config_file = self._generate_config_file(config="wrong config")
        with open(path_to_config_file, 'w') as f_out:
            f_out.write("some text, which broke json-format")

        with self.assertRaises(SystemExit) as exc:
            load_config(path_to_config_file)
        self.assertIsInstance(exc.exception, SystemExit)

    def test_validation_loaded_config(self):
        path_to_config_file = self._generate_config_file()
        config = load_config(path_to_config_file)

        self.assertTrue("REPORT_SIZE" in config)
        self.assertTrue("REPORT_DIR" in config)
        self.assertTrue("LOG_DIR" in config)
        self.assertEqual(len(config), 3)

    def test_take_last_log_file_plain(self):
        template = "nginx-access-ui.log-201706"
        log_name_list = [f"{template}{str(day).zfill(2)}" for day in range(1, 4)]
        log_file_path_list = [self._generate_plain_sample(log_name) for log_name in log_name_list]

        path_to_last_log_file = get_last_log_file(self.path_to_temp)
        self.assertTrue(path_to_last_log_file in log_file_path_list)
        self.assertEqual(path_to_last_log_file, log_file_path_list[-1])

    def test_take_last_log_file_gz(self):
        template = "nginx-access-ui.log-201706"
        log_name_list = [f"{template}{str(day).zfill(2)}" for day in range(1, 4)]
        log_file_path_list = [self._generate_gz_sample(log_name, is_remove_plain=True) for log_name in log_name_list]

        path_to_last_log_file = get_last_log_file(self.path_to_temp)
        self.assertTrue(path_to_last_log_file in log_file_path_list)
        self.assertEqual(path_to_last_log_file, log_file_path_list[-1])

    def test_take_last_log_file_gz_and_plain_mixed(self):
        template = "nginx-access-ui.log-201706"
        log_name_list = [f"{template}{str(day).zfill(2)}" for day in range(1, 4)]
        gz_list = [self._generate_gz_sample(log_name, is_remove_plain=True) for log_name in log_name_list]

        log_name_list = [f"{template}{str(day).zfill(2)}" for day in range(4, 6)]
        plain_list = [self._generate_plain_sample(log_name) for log_name in log_name_list]

        path_to_last_log_file = get_last_log_file(self.path_to_temp)
        self.assertTrue(path_to_last_log_file in plain_list)
        self.assertTrue(path_to_last_log_file not in gz_list)
        self.assertEqual(path_to_last_log_file, plain_list[-1])

    def test_take_last_log_wrong_format_date(self):
        self._generate_plain_sample("nginx-access-ui.log-01052017")

        with self.assertRaises(SystemExit) as exc:
            get_last_log_file(self.path_to_temp)

    def test_render_if_template_does_not_exist(self):
        table_json = self._generate_table_json()
        report_name = 'test_report.html'
        report_dir = os.path.join(self.path_to_temp, 'reports', )
        with self.assertRaises(SystemExit) as exc:
            render(table_json, report_name, report_dir, path_to_template='./some_wrong_path/report.html')

    def test_render_if_table_json_is_empty(self):
        report_name = 'test_report.html'
        report_dir = os.path.join(self.path_to_temp, 'reports', )
        path_to_template = os.path.join(self.abs_path, 'templates', 'report.html')
        render('', report_name, report_dir, path_to_template)
        self.assertTrue(os.path.exists(os.path.join(report_dir, report_name)))

    def test_render_if_report_dir_not_exist(self):
        report_dir = os.path.join(self.path_to_temp, 'reports', )

        self.assertFalse(os.path.exists(report_dir))

        path_to_template = os.path.join(self.abs_path, 'templates', 'report.html')
        render(self._generate_table_json(1), 'test_report.html', report_dir, path_to_template)

        self.assertTrue(os.path.exists(report_dir))

    def test_calculate_report_if_repot_size_default(self):
        path_to_file = self._generate_plain_sample("nginx-access-ui.log-20170630")
        table = calculate_report(path_to_file)
        self.assertIsInstance(table, list)
        self.assertTrue(len(table) > 0)

    def test_calculate_report_if_repot_size_equal_ten(self):
        path_to_file = self._generate_plain_sample("nginx-access-ui.log-20170630")
        report_size = 10
        table = calculate_report(path_to_file, size=report_size)
        self.assertTrue(len(table) == report_size)

    def test_extract_date_frome_normal_file_name(self):
        name = 'nginx-access-ui.log-20170630'
        self.assertIsInstance(extract_date_frome_file_name(name), datetime.date)

    def test_extract_date_frome_wrong_file_name(self):
        name = 'nginx-access.log-30062017'
        self.assertIsNone(extract_date_frome_file_name(name))

    def test_extract_date_frome_wrong_fomat_date_in_file_name(self):
        name = 'nginx-access-ui.log-30062017'

        with self.assertRaises(SystemExit):
            extract_date_frome_file_name(name)

    def test_openfile_if_plain(self):
        path_to_file = self._generate_plain_sample("nginx-access-ui.log-20170630")

        with openfile(path_to_file) as out_f:
            self.assertIsInstance(out_f.readline(), str)

    def test_openfile_if_gzip(self):
        path_to_file = self._generate_gz_sample("nginx-access-ui.log-20170630", is_remove_plain=True)

        with openfile(path_to_file, 'rb') as out_f:
            self.assertIsInstance(out_f.readline(), bytes)


if __name__ == '__main__':
    unittest.main()
