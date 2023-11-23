#!/usr/bin/env python3
#
#
#  IRIS wazuhindexer Source Code
#  Copyright (C) 2023 - SOCFortress
#  info@socfortress.co
#  Created by SOCFortress - 2023-03-06
#
#  License MIT


import traceback
from jinja2 import Template

from elasticsearch7 import Elasticsearch
import dateutil.parser
from datetime import datetime
import pytz

# utils
import operator

import iris_interface.IrisInterfaceStatus as InterfaceStatus
from app.datamgmt.manage.manage_attribute_db import add_tab_attribute_field

class Hit:
    def __init__(
        self,
        hitindex,
        hitid,
        image_name,
        process_guid,
        misp_category,
        misp_info,
        misp_comment,
        opencti_x_opencti_score,
        opencti_x_opencti_description,
        opencti_entity_type,
        opencti_i_created_at_day,
        agent_name,
        timestamp,
        time,
        dns_query_name,
    ):
        self.hitindex = hitindex
        self.hitid = hitid
        self.image_name = image_name
        self.process_guid = process_guid
        self.agent_name = agent_name
        self.misp_category = misp_category
        self.misp_info = misp_info
        self.misp_comment = misp_comment
        self.opencti_x_opencti_score = opencti_x_opencti_score
        self.opencti_x_opencti_description = opencti_x_opencti_description
        self.opencti_entity_type = opencti_entity_type
        self.opencti_i_created_at_day = opencti_i_created_at_day
        self.timestamp = timestamp
        self.time = time
        self.dns_query_name = dns_query_name

class WazuhindexerHandler(object):
    def __init__(self, mod_config, server_config, logger):
        self.mod_config = mod_config
        self.server_config = server_config
        self.wazuhindexer = self.get_wazuhindexer_instance()
        self.log = logger

    def get_wazuhindexer_instance(self):
        """
        Returns an wazuhindexer API instance depending if the key is premium or not

        :return: { cookiecutter.keyword }} Instance
        """
        url = self.mod_config.get('wazuhindexer_url')
        key = self.mod_config.get('wazuhindexer_key')
        proxies = {}

        if self.server_config.get('http_proxy'):
            proxies['https'] = self.server_config.get('HTTPS_PROXY')

        if self.server_config.get('https_proxy'):
            proxies['http'] = self.server_config.get('HTTP_PROXY')

        # TODO!
        # Here get your wazuhindexer instance and return it
        # ex: return wazuhindexerApi(url, key)
        return "<TODO>"

    def gen_report_from_template(self, html_template, wazuhindexer_report, total_hits) -> InterfaceStatus:
        """
        Generates an HTML report for Domain, displayed as an attribute in the IOC

        :param html_template: A string representing the HTML template
        :param misp_report: The JSON report fetched with wazuhindexer API
        :return: InterfaceStatus
        """
        template = Template(html_template)
        context = wazuhindexer_report
        pre_render = dict({"results": [], "total_hits": total_hits})

        for wazuhindexer_result in context:
            pre_render["results"].append(wazuhindexer_result)

        try:
            rendered = template.render(pre_render)

        except Exception:
            print(traceback.format_exc())
            self.log.error(traceback.format_exc())
            return InterfaceStatus.I2Error(traceback.format_exc())

        return InterfaceStatus.I2Success(data=rendered)

    def handle_domain(self, ioc):
        """
        Handles an IOC of type Domain and adds Wazuh-Indexer insights
        :param ioc: IOC instance
        :return: IIStatus
        """

        endpoint = self.mod_config.get("wazuhindexer_url")
        user = self.mod_config.get("wazuhindexer_user")
        password = self.mod_config.get("wazuhindexer_pass")
        index = self.mod_config.get("wazuhindexer_index")
        fields = self.mod_config.get("wazuhindexer_field_domain")
        size = self.mod_config.get("wazuhindexer_size")
        cert = self.mod_config.get("wazuhindexer_cert")
        verify = self.mod_config.get("wazuhindexer_ssl")

        self.log.info(f"Wazuh-Indexer Endpoint: {endpoint}")

        try:
            if user:
                es = Elasticsearch(
                    endpoint,
                    http_auth=(user, password),
                    verify_certs=verify,
                    timeout=30,
                )
            else:
                es = Elasticsearch(
                    endpoint, ca_certs=cert, verify_certs=verify, timeout=30
                )

            info = {}
            hits = []
            devices = []
            total = "eq"
            # query string to show kql search
            info["querystring"] = ""
            # populate logs
            self.log.info(f'Searching Wazuh-Indexer for: {ioc} contained within the field name {fields}')
            # dump all the ioc objects into a list
            objects = []
            objects.append(ioc)
            self.log.info(f'IOC Object: {objects}')

            # Call to Elasticsearch
            res = es.search(
                size=size,
                index=index,
                body={
                    "sort": [{"timestamp": {"order": "desc"}}],
                    "query": {
                        "multi_match": {"query": ioc.ioc_value, "fields": fields}
                    },
                },
            )
            total_hits = res["hits"]["total"]["value"]
            self.log.info(f'Total number of hits discovered: {total_hits}')
            # if relation is gte then more logs exist than we will display
            if (
                res["hits"]["total"]["relation"] == "gte"
                or res["hits"]["total"]["relation"] == "gt"
            ):
                total = "gte"
            # adding results from each query
            for hit in res["hits"]["hits"]:
                hitindex = hit["_index"]
                hitid = hit["_id"]
                # process fields
                image_name = ""
                process_guid = ""
                # misp fields
                misp_category = ""
                misp_info = ""
                misp_comment = ""
                # opencti fields
                opencti_x_opencti_score = ""
                opencti_x_opencti_description = ""
                opencti_entity_type = ""
                opencti_i_created_at_day = ""
                # host fields
                agent_name = ""
                # base fields
                timestamp = ""
                # dns fields
                dns_query_name = ""

                # base fields
                if "timestamp" in hit["_source"]:
                    if isinstance(hit["_source"]["timestamp"], str):
                        timestamp = dateutil.parser.parse(hit["_source"]["timestamp"])
                        time = timestamp.astimezone().strftime("%m/%d/%Y %I:%M %p")
                        timestamp = str(timestamp)
                    else:
                        timestamp = dateutil.parser.parse(
                            datetime.fromtimestamp(
                                float(hit["_source"]["timestamp"] / 1000)
                            ).strftime("%c")
                        )
                        time = timestamp.astimezone().strftime("%m/%d/%Y %I:%M %p")
                        timestamp = str(timestamp)
                    # host fields
                    if "agent_name" in hit["_source"]:
                        agent_name = hit["_source"]["agent_name"]
                        ioc.ioc_tags = f"{ioc.ioc_tags},{agent_name}:{timestamp}"
                    """
                    Set Fields for Windows
                    :param ioc: IOC instance
                    :return: IIStatus
                    """
                    # domain fields
                    if 'data_win_eventdata_queryName' in hit['_source']:
                        dns_query_name = hit['_source']['data_win_eventdata_queryName']

                    # image fields
                    if 'data_win_eventdata_image' in hit['_source']:
                        image_name = hit['_source']['data_win_eventdata_image']

                    # process fields
                    if 'data_win_eventdata_processGuid' in hit['_source']:
                        process_guid = hit['_source']['data_win_eventdata_processGuid']
                    """
                    Set Fields for Linux
                    :param ioc: IOC instance
                    :return: IIStatus
                    """
                    # domain fields
                    if 'data_dns_question_name' in hit['_source']:
                        dns_query_name = hit['_source']['data_dns_question_name']

                    # image fields
                    if 'data_win_eventdata_image' not in hit['_source']:
                        image_name = 'undected'

                    # process fields
                    if 'data_dns_id' in hit['_source']:
                        process_guid = hit['_source']['data_dns_id']

                    # misp fields
                    if 'misp_category' in hit['_source']:
                        misp_category = hit['_source']['misp_category']
                        misp_info = hit['_source']['misp_Event']['info']
                        misp_comment = hit['_source']['misp_comment']
                        ioc.ioc_tags = f"{ioc.ioc_tags},MISP Category:{misp_category}"

                    # opencti fields
                    if 'opencti_value' in hit['_source']:
                        opencti_x_opencti_score = hit['_source']['opencti_x_opencti_score']
                        opencti_x_opencti_description = hit['_source']['opencti_x_opencti_description']
                        opencti_entity_type = hit['_source']['opencti_entity_type']
                        opencti_i_created_at_day = hit['_source']['opencti_i_created_at_day']
                        ioc.ioc_tags = f"{ioc.ioc_tags},OpenCTI Score:{opencti_x_opencti_score}"

                    hits.append(
                        Hit(
                            hitindex,
                            hitid,
                            image_name,
                            process_guid,
                            misp_category,
                            misp_info,
                            misp_comment,
                            opencti_x_opencti_score,
                            opencti_x_opencti_description,
                            opencti_entity_type,
                            opencti_i_created_at_day,
                            agent_name,
                            timestamp,
                            time,
                            dns_query_name,
                        )
                    )

            # sort the hits based on timestamp
            hits.sort(key=operator.attrgetter("timestamp"), reverse=True)
            hits = [ob.__dict__ for ob in hits]

        except Exception as e:
            print(traceback.format_exc())
            self.log.error(traceback.format_exc())
            return InterfaceStatus.I2Error(traceback.format_exc())

        # TODO! do your stuff, then report it to the element (here an IOC)

        if self.mod_config.get("wazuhindexer_report_as_attribute") is True:
            self.log.info("Adding new attribute Wazuh-Indexer Report to IOC")

            report = hits

            status = self.gen_report_from_template(
                self.mod_config.get("wazuhindexer_ioc_report_template"), report, total_hits
            )

            if not status.is_success():
                return status

            rendered_report = status.get_data()

            try:
                add_tab_attribute_field(
                    ioc,
                    tab_name="Wazuh-Indexer Report",
                    field_name="HTML report",
                    field_type="html",
                    field_value=rendered_report,
                )

            except Exception:

                self.log.error(traceback.format_exc())
                return InterfaceStatus.I2Error(traceback.format_exc())
        else:
            self.log.info("Skipped adding attribute report. Option disabled")

        return InterfaceStatus.I2Success()
    
    def handle_ip(self, ioc):
        """
        Handles an IOC of type IP and adds Wazuh-Indexer insights
        :param ioc: IOC instance
        :return: IIStatus
        """

        endpoint = self.mod_config.get("wazuhindexer_url")
        user = self.mod_config.get("wazuhindexer_user")
        password = self.mod_config.get("wazuhindexer_pass")
        index = self.mod_config.get("wazuhindexer_index")
        fields = self.mod_config.get("wazuhindexer_field_ip")
        size = self.mod_config.get("wazuhindexer_size")
        cert = self.mod_config.get("wazuhindexer_cert")
        verify = self.mod_config.get("wazuhindexer_ssl")

        print(f"Wazuh-Indexer Endpoint: {endpoint}")

        try:
            if user:
                es = Elasticsearch(
                    endpoint,
                    http_auth=(user, password),
                    verify_certs=verify,
                    timeout=30,
                )
            else:
                es = Elasticsearch(
                    endpoint, ca_certs=cert, verify_certs=verify, timeout=30
                )

            info = {}
            hits = []
            devices = []
            total = "eq"
            # query string to show kql search
            info["querystring"] = ""
            # populate logs
            self.log.info(f'Searching Wazuh-Indexer for: {ioc} contained within the field name {fields}')
            # Call to Elasticsearch
            res = es.search(
                size=size,
                index=index,
                body={
                    "sort": [{"timestamp": {"order": "desc"}}],
                    "query": {
                        "multi_match": {"query": ioc.ioc_value, "fields": fields}
                    },
                },
            )
            total_hits = res["hits"]["total"]["value"]
            self.log.info(f'Total number of hits discovered: {total_hits}')
            # if relation is gte then more logs exist than we will display
            if (
                res["hits"]["total"]["relation"] == "gte"
                or res["hits"]["total"]["relation"] == "gt"
            ):
                total = "gte"
            # adding results from each query
            for hit in res["hits"]["hits"]:
                hitindex = hit["_index"]
                hitid = hit["_id"]
                # process fields
                image_name = ""
                process_guid = ""
                # misp fields
                misp_category = ""
                misp_info = ""
                misp_comment = ""
                # opencti fields
                opencti_x_opencti_score = ""
                opencti_x_opencti_description = ""
                opencti_entity_type = ""
                opencti_i_created_at_day = ""
                # host fields
                agent_name = ""
                # base fields
                timestamp = ""
                # ip fields
                destination_ip = ""
                destination_country = ""
                destination_port = ""

                # base fields
                if "timestamp" in hit["_source"]:
                    if isinstance(hit["_source"]["timestamp"], str):
                        timestamp = dateutil.parser.parse(hit["_source"]["timestamp"])
                        time = timestamp.astimezone().strftime("%m/%d/%Y %I:%M %p")
                        timestamp = str(timestamp)
                    else:
                        timestamp = dateutil.parser.parse(
                            datetime.fromtimestamp(
                                float(hit["_source"]["timestamp"] / 1000)
                            ).strftime("%c")
                        )
                        time = timestamp.astimezone().strftime("%m/%d/%Y %I:%M %p")
                        timestamp = str(timestamp)
                    # host fields
                    if "agent_name" in hit["_source"]:
                        agent_name = hit["_source"]["agent_name"]
                        ioc.ioc_tags = f"{ioc.ioc_tags},{agent_name}:{timestamp}"
                    """
                    Set Fields for Windows
                    :param ioc: IOC instance
                    :return: IIStatus
                    """
                    # ip fields
                    if 'data_win_eventdata_destinationIp' in hit['_source']:
                        destination_ip = hit['_source']['data_win_eventdata_destinationIp']

                    if 'data_win_eventdata_destinationIp_country_code' in hit['_source']:
                        destination_country = hit['_source']['data_win_eventdata_destinationIp_country_code']

                    if 'data_win_eventdata_destinationPort' in hit['_source']:
                        destination_port = hit['_source']['data_win_eventdata_destinationPort']

                    # image fields
                    if 'data_win_eventdata_image' in hit['_source']:
                        image_name = hit['_source']['data_win_eventdata_image']

                    # process fields
                    if 'data_win_eventdata_processGuid' in hit['_source']:
                        process_guid = hit['_source']['data_win_eventdata_processGuid']
                    """
                    Set Fields for Linux
                    :param ioc: IOC instance
                    :return: IIStatus
                    """
                    # ip fields
                    if 'data_destination_ip' in hit['_source']:
                        destination_ip = hit['_source']['data_destination_ip']

                    if 'data_destination_ip_country_code' in hit['_source']:
                        destination_country = hit['_source']['data_destination_ip_country_code']

                    if 'data_destination_port' in hit['_source']:
                        destination_port = hit['_source']['data_destination_port']

                    # image fields
                    if 'data_win_eventdata_image' not in hit['_source']:
                        image_name = 'undetected'

                    # process fields
                    if 'data_win_eventdata_processGuid' not in hit['_source']:
                        process_guid = 'undetected'

                    # misp fields
                    if 'misp_category' in hit['_source']:
                        misp_category = hit['_source']['misp_category']
                        misp_info = hit['_source']['misp_Event']['info']
                        misp_comment = hit['_source']['misp_comment']
                        ioc.ioc_tags = f"{ioc.ioc_tags},MISP Category:{misp_category}"

                    # opencti fields
                    if 'opencti_value' in hit['_source']:
                        opencti_x_opencti_score = hit['_source']['opencti_x_opencti_score']
                        opencti_x_opencti_description = hit['_source']['opencti_x_opencti_description']
                        opencti_entity_type = hit['_source']['opencti_entity_type']
                        opencti_i_created_at_day = hit['_source']['opencti_i_created_at_day']
                        ioc.ioc_tags = f"{ioc.ioc_tags},OpenCTI Score:{opencti_x_opencti_score}"

                    hits.append(
                        Hit(
                            hitindex,
                            hitid,
                            image_name,
                            process_guid,
                            misp_category,
                            misp_info,
                            misp_comment,
                            opencti_x_opencti_score,
                            opencti_x_opencti_description,
                            opencti_entity_type,
                            opencti_i_created_at_day,
                            agent_name,
                            timestamp,
                            time,
                            destination_ip,
                            destination_country,
                            destination_port,
                        )
                    )

            # sort the hits based on timestamp
            hits.sort(key=operator.attrgetter("timestamp"), reverse=True)
            hits = [ob.__dict__ for ob in hits]

            print(hits)

        except Exception as e:
            print(traceback.format_exc())
            self.log.error(traceback.format_exc())
            return InterfaceStatus.I2Error(traceback.format_exc())

        # TODO! do your stuff, then report it to the element (here an IOC)

        if self.mod_config.get("wazuhindexer_report_as_attribute") is True:
            self.log.info("Adding new attribute Wazuh-Indexer Report to IOC")

            report = hits

            status = self.gen_report_from_template(
                self.mod_config.get("wazuhindexer_ioc_report_template"), report, total_hits
            )

            if not status.is_success():
                return status

            rendered_report = status.get_data()

            try:
                add_tab_attribute_field(
                    ioc,
                    tab_name="Wazuh-Indexer Report",
                    field_name="HTML report",
                    field_type="html",
                    field_value=rendered_report,
                )

            except Exception:

                self.log.error(traceback.format_exc())
                return InterfaceStatus.I2Error(traceback.format_exc())
        else:
            self.log.info("Skipped adding attribute report. Option disabled")

        return InterfaceStatus.I2Success()

    def handle_filehash(self, ioc):
        """
        Handles an IOC of type sha256 and adds Wazuh-Indexer insights
        :param ioc: IOC instance
        :return: IIStatus
        """

        endpoint = self.mod_config.get("wazuhindexer_url")
        user = self.mod_config.get("wazuhindexer_user")
        password = self.mod_config.get("wazuhindexer_pass")
        index = self.mod_config.get("wazuhindexer_index")
        fields = self.mod_config.get("wazuhindexer_field_sha256")
        size = self.mod_config.get("wazuhindexer_size")
        cert = self.mod_config.get("wazuhindexer_cert")
        verify = self.mod_config.get("wazuhindexer_ssl")

        print(f"Wazuh-Indexer Endpoint: {endpoint}")

        try:
            if user:
                es = Elasticsearch(
                    endpoint,
                    http_auth=(user, password),
                    verify_certs=verify,
                    timeout=30,
                )
            else:
                es = Elasticsearch(
                    endpoint, ca_certs=cert, verify_certs=verify, timeout=30
                )

            info = {}
            hits = []
            devices = []
            total = "eq"
            # query string to show kql search
            info["querystring"] = ""
            # populate logs
            self.log.info(f'Searching Wazuh-Indexer for: {ioc} contained within the field name {fields}')
            # Call to Elasticsearch
            res = es.search(
                size=size,
                index=index,
                body={
                    "sort": [{"timestamp": {"order": "desc"}}],
                    "query": {
                        "multi_match": {"query": ioc.ioc_value, "fields": fields}
                    },
                },
            )
            total_hits = res["hits"]["total"]["value"]
            self.log.info(f'Total number of hits discovered: {total_hits}')
            # if relation is gte then more logs exist than we will display
            if (
                res["hits"]["total"]["relation"] == "gte"
                or res["hits"]["total"]["relation"] == "gt"
            ):
                total = "gte"
            # adding results from each query
            for hit in res["hits"]["hits"]:
                hitindex = hit["_index"]
                hitid = hit["_id"]
                # process fields
                image_name = ""
                process_guid = ""
                # misp fields
                misp_category = ""
                misp_info = ""
                misp_comment = ""
                # opencti fields
                opencti_x_opencti_score = ""
                opencti_x_opencti_description = ""
                opencti_entity_type = ""
                opencti_i_created_at_day = ""
                # host fields
                agent_name = ""
                # base fields
                timestamp = ""
                # file hash fields
                file_path = ""
                sha256 = ""
                user_name = ""

                # base fields
                if "timestamp" in hit["_source"]:
                    if isinstance(hit["_source"]["timestamp"], str):
                        timestamp = dateutil.parser.parse(hit["_source"]["timestamp"])
                        time = timestamp.astimezone().strftime("%m/%d/%Y %I:%M %p")
                        timestamp = str(timestamp)
                    else:
                        timestamp = dateutil.parser.parse(
                            datetime.fromtimestamp(
                                float(hit["_source"]["timestamp"] / 1000)
                            ).strftime("%c")
                        )
                        time = timestamp.astimezone().strftime("%m/%d/%Y %I:%M %p")
                        timestamp = str(timestamp)
                    # host fields
                    if "agent_name" in hit["_source"]:
                        agent_name = hit["_source"]["agent_name"]
                        ioc.ioc_tags = f"{ioc.ioc_tags},{agent_name}:{timestamp}"
                    """
                    Set Fields for Windows
                    :param ioc: IOC instance
                    :return: IIStatus
                    """
                    # file hash fields
                    if 'sha256' in hit['_source']:
                        sha256 = hit['_source']['sha256']

                    if 'syscheck_path' in hit['_source']:
                        file_path = hit['_source']['syscheck_path']
                    
                    if 'syscheck_uname_after' in hit['_source']:
                        user_name = hit['_source']['syscheck_uname_after']

                    # image fields
                    if 'data_win_eventdata_image' in hit['_source']:
                        image_name = hit['_source']['data_win_eventdata_image']

                    # process fields
                    if 'data_win_eventdata_processGuid' in hit['_source']:
                        process_guid = hit['_source']['data_win_eventdata_processGuid']
                    """
                    Set Fields for Linux
                    :param ioc: IOC instance
                    :return: IIStatus
                    """
                    # file hash fields
                    if 'sha256' in hit['_source']:
                        sha256 = hit['_source']['sha256']

                    if 'syscheck_path' in hit['_source']:
                        file_path = hit['_source']['syscheck_path']
                    
                    if 'syscheck_uname_after' in hit['_source']:
                        user_name = hit['_source']['syscheck_uname_after']

                    # image fields
                    if 'data_win_eventdata_image' not in hit['_source']:
                        image_name = 'undetected'

                    # process fields
                    if 'data_win_eventdata_processGuid' not in hit['_source']:
                        process_guid = 'undetected'

                    # misp fields
                    if 'misp_category' in hit['_source']:
                        misp_category = hit['_source']['misp_category']
                        misp_info = hit['_source']['misp_Event']['info']
                        misp_comment = hit['_source']['misp_comment']
                        ioc.ioc_tags = f"{ioc.ioc_tags},MISP Category:{misp_category}"

                    # opencti fields
                    if 'opencti_value' in hit['_source']:
                        opencti_x_opencti_score = hit['_source']['opencti_x_opencti_score']
                        opencti_x_opencti_description = hit['_source']['opencti_x_opencti_description']
                        opencti_entity_type = hit['_source']['opencti_entity_type']
                        opencti_i_created_at_day = hit['_source']['opencti_i_created_at_day']
                        ioc.ioc_tags = f"{ioc.ioc_tags},OpenCTI Score:{opencti_x_opencti_score}"

                    hits.append(
                        Hit(
                            hitindex,
                            hitid,
                            image_name,
                            process_guid,
                            misp_category,
                            misp_info,
                            misp_comment,
                            opencti_x_opencti_score,
                            opencti_x_opencti_description,
                            opencti_entity_type,
                            opencti_i_created_at_day,
                            agent_name,
                            timestamp,
                            time,
                            file_path,
                            sha256,
                            user_name,
                        )
                    )

            # sort the hits based on timestamp
            hits.sort(key=operator.attrgetter("timestamp"), reverse=True)
            hits = [ob.__dict__ for ob in hits]

            print(hits)

        except Exception as e:
            print(traceback.format_exc())
            self.log.error(traceback.format_exc())
            return InterfaceStatus.I2Error(traceback.format_exc())

        # TODO! do your stuff, then report it to the element (here an IOC)

        if self.mod_config.get("wazuhindexer_report_as_attribute") is True:
            self.log.info("Adding new attribute Wazuh-Indexer File Hash Report to IOC")

            report = hits

            status = self.gen_report_from_template(
                self.mod_config.get("wazuhindexer_ioc_report_template"), report, total_hits
            )

            if not status.is_success():
                return status

            rendered_report = status.get_data()

            try:
                add_tab_attribute_field(
                    ioc,
                    tab_name="Wazuh-Indexer Report",
                    field_name="HTML report",
                    field_type="html",
                    field_value=rendered_report,
                )

            except Exception:

                self.log.error(traceback.format_exc())
                return InterfaceStatus.I2Error(traceback.format_exc())
        else:
            self.log.info("Skipped adding attribute report. Option disabled")

        return InterfaceStatus.I2Success()

    def handle_filename(self, ioc):
        """
        Handles an IOC of type filename and adds Wazuh-Indexer insights
        :param ioc: IOC instance
        :return: IIStatus
        """

        endpoint = self.mod_config.get("wazuhindexer_url")
        user = self.mod_config.get("wazuhindexer_user")
        password = self.mod_config.get("wazuhindexer_pass")
        index = self.mod_config.get("wazuhindexer_index")
        fields = self.mod_config.get("wazuhindexer_field_fileName")
        size = self.mod_config.get("wazuhindexer_size")
        cert = self.mod_config.get("wazuhindexer_cert")
        verify = self.mod_config.get("wazuhindexer_ssl")

        print(f"Wazuh-Indexer Endpoint: {endpoint}")

        try:
            if user:
                es = Elasticsearch(
                    endpoint,
                    http_auth=(user, password),
                    verify_certs=verify,
                    timeout=30,
                )
            else:
                es = Elasticsearch(
                    endpoint, ca_certs=cert, verify_certs=verify, timeout=30
                )

            info = {}
            hits = []
            devices = []
            total = "eq"
            # query string to show kql search
            info["querystring"] = ""
            # populate logs
            self.log.info(f'Searching Wazuh-Indexer for: {ioc.ioc_value} contained within the field name {fields}')
            # Call to Elasticsearch
            res = es.search(
                size=size,
                index=index,
                body={
                    "sort": [{"timestamp": {"order": "desc"}}],
                    "query": {
                        "multi_match": {"query": ioc.ioc_value, "fields": fields}
                    },
                },
            )
            total_hits = res["hits"]["total"]["value"]
            self.log.info(f'Total number of hits discovered: {total_hits}')
            # if relation is gte then more logs exist than we will display
            if (
                res["hits"]["total"]["relation"] == "gte"
                or res["hits"]["total"]["relation"] == "gt"
            ):
                total = "gte"
            # adding results from each query
            for hit in res["hits"]["hits"]:
                hitindex = hit["_index"]
                hitid = hit["_id"]
                # process fields
                image_name = ""
                process_guid = ""
                # misp fields
                misp_category = ""
                misp_info = ""
                misp_comment = ""
                # opencti fields
                opencti_x_opencti_score = ""
                opencti_x_opencti_description = ""
                opencti_entity_type = ""
                opencti_i_created_at_day = ""
                # host fields
                agent_name = ""
                # base fields
                timestamp = ""
                # filename fields
                file_name = ""
                user_name = ""

                # base fields
                if "timestamp" in hit["_source"]:
                    if isinstance(hit["_source"]["timestamp"], str):
                        timestamp = dateutil.parser.parse(hit["_source"]["timestamp"])
                        time = timestamp.astimezone().strftime("%m/%d/%Y %I:%M %p")
                        timestamp = str(timestamp)
                    else:
                        timestamp = dateutil.parser.parse(
                            datetime.fromtimestamp(
                                float(hit["_source"]["timestamp"] / 1000)
                            ).strftime("%c")
                        )
                        time = timestamp.astimezone().strftime("%m/%d/%Y %I:%M %p")
                        timestamp = str(timestamp)
                    # host fields
                    if "agent_name" in hit["_source"]:
                        agent_name = hit["_source"]["agent_name"]
                        ioc.ioc_tags = f"{ioc.ioc_tags},{agent_name}:{timestamp}"
                    """
                    Set Fields for Windows
                    :param ioc: IOC instance
                    :return: IIStatus
                    """
                    # file name fields
                    if 'data_win_eventdata_targetFilename' in hit['_source']:
                        file_name = hit['_source']['data_win_eventdata_targetFilename']

                    if 'data_win_eventdata_user' in hit['_source']:
                        user_name = hit['_source']['data_win_eventdata_user']

                    # image fields
                    if 'data_win_eventdata_image' in hit['_source']:
                        image_name = hit['_source']['data_win_eventdata_image']

                    # process fields
                    if 'data_win_eventdata_processGuid' in hit['_source']:
                        process_guid = hit['_source']['data_win_eventdata_processGuid']
                    """
                    Set Fields for Linux
                    :param ioc: IOC instance
                    :return: IIStatus
                    """
                    # file name fields
                    if 'syscheck_path' in hit['_source']:
                        file_name = hit['_source']['syscheck_path']

                    if 'syscheck_gname_after' in hit['_source']:
                        user_name = hit['_source']['syscheck_gname_after']

                    # image fields
                    if 'data_win_eventdata_image' not in hit['_source']:
                        image_name = 'undetected'

                    # process fields
                    if 'data_win_eventdata_processGuid' not in hit['_source']:
                        process_guid = 'undetected'

                    # misp fields
                    if 'misp_category' in hit['_source']:
                        misp_category = hit['_source']['misp_category']
                        misp_info = hit['_source']['misp_Event']['info']
                        misp_comment = hit['_source']['misp_comment']
                        ioc.ioc_tags = f"{ioc.ioc_tags},MISP Category:{misp_category}"

                    # opencti fields
                    if 'opencti_value' in hit['_source']:
                        opencti_x_opencti_score = hit['_source']['opencti_x_opencti_score']
                        opencti_x_opencti_description = hit['_source']['opencti_x_opencti_description']
                        opencti_entity_type = hit['_source']['opencti_entity_type']
                        opencti_i_created_at_day = hit['_source']['opencti_i_created_at_day']
                        ioc.ioc_tags = f"{ioc.ioc_tags},OpenCTI Score:{opencti_x_opencti_score}"

                    hits.append(
                        Hit(
                            hitindex,
                            hitid,
                            image_name,
                            process_guid,
                            misp_category,
                            misp_info,
                            misp_comment,
                            opencti_x_opencti_score,
                            opencti_x_opencti_description,
                            opencti_entity_type,
                            opencti_i_created_at_day,
                            agent_name,
                            timestamp,
                            time,
                            file_name,
                            user_name,
                        )
                    )

            # sort the hits based on timestamp
            hits.sort(key=operator.attrgetter("timestamp"), reverse=True)
            hits = [ob.__dict__ for ob in hits]

            print(hits)

        except Exception as e:
            print(traceback.format_exc())
            self.log.error(traceback.format_exc())
            return InterfaceStatus.I2Error(traceback.format_exc())

        # TODO! do your stuff, then report it to the element (here an IOC)

        if self.mod_config.get("wazuhindexer_report_as_attribute") is True:
            self.log.info("Adding new attribute Wazuh-Indexer File Name Report to IOC")

            report = hits

            status = self.gen_report_from_template(
                self.mod_config.get("wazuhindexer_ioc_report_template"), report, total_hits
            )

            if not status.is_success():
                return status

            rendered_report = status.get_data()

            try:
                add_tab_attribute_field(
                    ioc,
                    tab_name="Wazuh-Indexer Report",
                    field_name="HTML report",
                    field_type="html",
                    field_value=rendered_report,
                )

            except Exception:

                self.log.error(traceback.format_exc())
                return InterfaceStatus.I2Error(traceback.format_exc())
        else:
            self.log.info("Skipped adding attribute report. Option disabled")

        return InterfaceStatus.I2Success()