"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'format_start_info' block
    format_start_info(container=container)

    return

@phantom.playbook_block()
def hunt_ip_splunk(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("hunt_ip_splunk() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    query_formatted_string = phantom.format(
        container=container,
        template="""index=main sourcetype=sophos* src_ip={0} OR dst_ip={0} | table src_ip, dst_ip | dedup src_ip, dst_ip | eval host=if(src_ip=\"{0}\",dst_ip,src_ip) | dedup host\n""",
        parameters=[
            "playbook_input:ip"
        ])

    playbook_input_ip = phantom.collect2(container=container, datapath=["playbook_input:ip"])

    parameters = []

    # build parameters list for 'hunt_ip_splunk' call
    for playbook_input_ip_item in playbook_input_ip:
        if query_formatted_string is not None:
            parameters.append({
                "query": query_formatted_string,
                "command": "search",
                "start_time": "",
                "search_mode": "smart",
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="hunt_ip_splunk", assets=["splunk"], callback=decision_found_ioc)

    return


@phantom.playbook_block()
def get_compromised_ip_hostname_and_users(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_compromised_ip_hostname_and_users() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    query_formatted_string = phantom.format(
        container=container,
        template="""sourcetype=\"WinEventLog:Microsoft-Windows-Sysmon/Operational\" EventCode=22 QueryResults=*{0}* | dedup host | table host | join host[search sourcetype=\"WinEventLog:Microsoft-Windows-Sysmon/Operational\"host=\"vm-windows-client\" | dedup User | rex field=_raw \"User:\\s.*\\\\\\\\(?<username>.+)\" | fields username, host | where !isnull(username) | stats list(username) delim=\",\" as active_usernames by host]""",
        parameters=[
            "hunt_ip_splunk:action_result.data.*.host"
        ])

    hunt_ip_splunk_result_data = phantom.collect2(container=container, datapath=["hunt_ip_splunk:action_result.data.*.host","hunt_ip_splunk:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'get_compromised_ip_hostname_and_users' call
    for hunt_ip_splunk_result_item in hunt_ip_splunk_result_data:
        if query_formatted_string is not None:
            parameters.append({
                "query": query_formatted_string,
                "command": "search",
                "start_time": "",
                "search_mode": "smart",
                "context": {'artifact_id': hunt_ip_splunk_result_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="get_compromised_ip_hostname_and_users", assets=["splunk"], callback=format_found_ioc)

    return


@phantom.playbook_block()
def decision_found_ioc(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_found_ioc() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["hunt_ip_splunk:action_result.data.*.host", "!=", ""]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        get_all_traffic_to_and_from_ioc_ip(action=action, success=success, container=container, results=results, handle=handle)
        get_compromised_ip_hostname_and_users(action=action, success=success, container=container, results=results, handle=handle)
        create_ip_object(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    comment_ioc_not_exist(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def comment_ioc_not_exist(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("comment_ioc_not_exist() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="IOCs does not exists")

    join_format_incident_info_1(container=container)

    return


@phantom.playbook_block()
def get_all_traffic_to_and_from_ioc_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_all_traffic_to_and_from_ioc_ip() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    query_formatted_string = phantom.format(
        container=container,
        template="""index=main sourcetype=sophos* (src_ip={0} AND dst_ip={1}) OR (dst_ip={0} AND src_ip={1}) | table action, src_ip, src_port, dst_ip, dst_port, fw_rule_name, _time\n""",
        parameters=[
            "hunt_ip_splunk:action_result.data.*.host",
            "playbook_input:ip"
        ])

    hunt_ip_splunk_result_data = phantom.collect2(container=container, datapath=["hunt_ip_splunk:action_result.data.*.host","hunt_ip_splunk:action_result.parameter.context.artifact_id"], action_results=results)
    playbook_input_ip = phantom.collect2(container=container, datapath=["playbook_input:ip"])

    parameters = []

    # build parameters list for 'get_all_traffic_to_and_from_ioc_ip' call
    for hunt_ip_splunk_result_item in hunt_ip_splunk_result_data:
        for playbook_input_ip_item in playbook_input_ip:
            if query_formatted_string is not None:
                parameters.append({
                    "query": query_formatted_string,
                    "command": "search",
                    "search_mode": "smart",
                    "context": {'artifact_id': hunt_ip_splunk_result_item[1]},
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="get_all_traffic_to_and_from_ioc_ip", assets=["splunk"], callback=correlate_traffic_to_process)

    return


@phantom.playbook_block()
def comment_start_info(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("comment_start_info() called")

    format_start_info = phantom.get_format_data(name="format_start_info")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=format_start_info)

    hunt_ip_splunk(container=container)

    return


@phantom.playbook_block()
def format_start_info(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_start_info() called")

    template = """Hunt IP playbook started hunt for IP: {0}"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_input:ip"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_start_info")

    comment_start_info(container=container)

    return


@phantom.playbook_block()
def ip_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("ip_reputation_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ip_formatted_string = phantom.format(
        container=container,
        template="""{0}\n""",
        parameters=[
            "playbook_input:ip"
        ])

    playbook_input_ip = phantom.collect2(container=container, datapath=["playbook_input:ip"])

    parameters = []

    # build parameters list for 'ip_reputation_1' call
    for playbook_input_ip_item in playbook_input_ip:
        if ip_formatted_string is not None:
            parameters.append({
                "ip": ip_formatted_string,
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("ip reputation", parameters=parameters, name="ip_reputation_1", assets=["virustotal"], callback=decision_virustotal_ip_found)

    return


@phantom.playbook_block()
def geolocate_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("geolocate_ip_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ip_formatted_string = phantom.format(
        container=container,
        template="""{0}\n""",
        parameters=[
            "playbook_input:ip"
        ])

    playbook_input_ip = phantom.collect2(container=container, datapath=["playbook_input:ip"])

    parameters = []

    # build parameters list for 'geolocate_ip_1' call
    for playbook_input_ip_item in playbook_input_ip:
        if ip_formatted_string is not None:
            parameters.append({
                "ip": ip_formatted_string,
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("geolocate ip", parameters=parameters, name="geolocate_ip_1", assets=["maxmind"], callback=format_geolocate_result)

    return


@phantom.playbook_block()
def format_whois_result(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_whois_result() called")

    template = """WHOIS ip result for IP {0}:\n\n{1}"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_input:ip",
        "whois_ip_1:action_result.message"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_whois_result")

    comment_whois_result(container=container)

    return


@phantom.playbook_block()
def format_geolocate_result(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_geolocate_result() called")

    template = """MaxMind geolocate result for {0}:\n\nCountry: {1} ({2}), {3}\nState: {4}\nCity: {5}\nOrg: {6}\n"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_input:ip",
        "geolocate_ip_1:action_result.summary.country",
        "geolocate_ip_1:action_result.data.*.country_iso_code",
        "geolocate_ip_1:action_result.data.*.continent_name",
        "geolocate_ip_1:action_result.summary.state",
        "geolocate_ip_1:action_result.summary.city",
        "geolocate_ip_1:action_result.data.*.as_org"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_geolocate_result")

    comment_geolocate_result(container=container)

    return


@phantom.playbook_block()
def decision_virustotal_ip_found(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_virustotal_ip_found() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["ip_reputation_1:action_result.data.*.response_code", "==", 0]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        format_ip_reputation_no_result(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    format_ip_reputation_result(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def format_ip_reputation_no_result(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_ip_reputation_no_result() called")

    template = """IP-address {0} not found in VirusTotal database. """

    # parameter list for template variable replacement
    parameters = [
        "playbook_input:ip"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_ip_reputation_no_result")

    comment_ip_reputation_no_result(container=container)

    return


@phantom.playbook_block()
def format_ip_reputation_result(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_ip_reputation_result() called")

    template = """VirusTotal IP reputation check for {0}:\n\n{1}\n"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_input:ip",
        "ip_reputation_1:action_result.message"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_ip_reputation_result")

    comment_ip_reputation_result(container=container)

    return


@phantom.playbook_block()
def comment_whois_result(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("comment_whois_result() called")

    format_whois_result = phantom.get_format_data(name="format_whois_result")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=format_whois_result)

    return


@phantom.playbook_block()
def comment_ip_reputation_no_result(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("comment_ip_reputation_no_result() called")

    format_ip_reputation_no_result = phantom.get_format_data(name="format_ip_reputation_no_result")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=format_ip_reputation_no_result)

    return


@phantom.playbook_block()
def comment_ip_reputation_result(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("comment_ip_reputation_result() called")

    format_ip_reputation_result = phantom.get_format_data(name="format_ip_reputation_result")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=format_ip_reputation_result)

    return


@phantom.playbook_block()
def comment_geolocate_result(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("comment_geolocate_result() called")

    format_geolocate_result = phantom.get_format_data(name="format_geolocate_result")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=format_geolocate_result)

    return


@phantom.playbook_block()
def format_found_ioc(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_found_ioc() called")

    template = """Found IOC {0} in logs communicating with {1}. Running investigations on {0}. \n"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_input:ip",
        "get_compromised_ip_hostname_and_users:action_result.data.*.host"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_found_ioc")

    comment_found_ioc(container=container)

    return


@phantom.playbook_block()
def comment_found_ioc(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("comment_found_ioc() called")

    format_found_ioc = phantom.get_format_data(name="format_found_ioc")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=format_found_ioc)

    ip_reputation_1(container=container)
    geolocate_ip_1(container=container)
    whois_ip_1(container=container)

    return


@phantom.playbook_block()
def whois_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("whois_ip_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ip_formatted_string = phantom.format(
        container=container,
        template="""{0}\n""",
        parameters=[
            "playbook_input:ip"
        ])

    playbook_input_ip = phantom.collect2(container=container, datapath=["playbook_input:ip"])

    parameters = []

    # build parameters list for 'whois_ip_1' call
    for playbook_input_ip_item in playbook_input_ip:
        if ip_formatted_string is not None:
            parameters.append({
                "ip": ip_formatted_string,
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("whois ip", parameters=parameters, name="whois_ip_1", assets=["whois"], callback=format_whois_result)

    return


@phantom.playbook_block()
def correlate_traffic_to_process(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("correlate_traffic_to_process() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    query_formatted_string = phantom.format(
        container=container,
        template="""index=main sourcetype=\"WinEventLog:Microsoft-Windows-Sysmon/Operational\" EventCode=3 (SourceIp={1} AND DestinationIp={2}) SourcePort IN ({0}) | join ProcessGuid\n    [search sourcetype=\"WinEventLog:Microsoft-Windows-Sysmon/Operational\" EventCode=1\n    | fields ProcessGuid, CommandLine, Image\n    | rex field=_raw \"CommandLine: .+['\\\"]*(?<malicious_FilePath>C:[\\\\\\\\\\w\\.]+)['\\\"]*\"]\n| stats list(SourcePort) as \"src_port used\", list(ProcessGuid) as \"Process GUID used\" by malicious_FilePath\n""",
        parameters=[
            "get_all_traffic_to_and_from_ioc_ip:action_result.data.*.src_port",
            "hunt_ip_splunk:action_result.data.*.host",
            "playbook_input:ip"
        ])

    ################################################################################
    # Correlates firewall logs with symon logs to find the malicious process
    ################################################################################

    get_all_traffic_to_and_from_ioc_ip_result_data = phantom.collect2(container=container, datapath=["get_all_traffic_to_and_from_ioc_ip:action_result.data.*.src_port","get_all_traffic_to_and_from_ioc_ip:action_result.parameter.context.artifact_id"], action_results=results)
    hunt_ip_splunk_result_data = phantom.collect2(container=container, datapath=["hunt_ip_splunk:action_result.data.*.host","hunt_ip_splunk:action_result.parameter.context.artifact_id"], action_results=results)
    playbook_input_ip = phantom.collect2(container=container, datapath=["playbook_input:ip"])

    parameters = []

    # build parameters list for 'correlate_traffic_to_process' call
    for get_all_traffic_to_and_from_ioc_ip_result_item in get_all_traffic_to_and_from_ioc_ip_result_data:
        for hunt_ip_splunk_result_item in hunt_ip_splunk_result_data:
            for playbook_input_ip_item in playbook_input_ip:
                if query_formatted_string is not None:
                    parameters.append({
                        "query": query_formatted_string,
                        "command": "search",
                        "search_mode": "smart",
                        "context": {'artifact_id': hunt_ip_splunk_result_item[1]},
                    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="correlate_traffic_to_process", assets=["splunk"], callback=format_found_process)

    return


@phantom.playbook_block()
def comment_found_process(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("comment_found_process() called")

    ################################################################################
    # Malicious process found: 
    ################################################################################

    format_found_process = phantom.get_format_data(name="format_found_process")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=format_found_process)

    get_file(container=container)

    return


@phantom.playbook_block()
def format_found_process(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_found_process() called")

    template = """Malicious file found: {0}\nStarting remediation actions on the file."""

    # parameter list for template variable replacement
    parameters = [
        "correlate_traffic_to_process:action_result.data.*.malicious_FilePath"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_found_process")

    comment_found_process(container=container)

    return


@phantom.playbook_block()
def create_ip_object(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("create_ip_object() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    location_formatted_string = phantom.format(
        container=container,
        template="""webconsole/APIController?SecureStorageMasterKey=Passw0rd@12345&reqxml=<Request><Login><Username>API admin</Username><Password>7tE4s8)TTV</Password></Login><Set><IPHost><Name>{0}</Name><IPFamily>IPv4</IPFamily><HostType>IP</HostType><IPAddress>{0}</IPAddress></IPHost></Set></Request>""",
        parameters=[
            "playbook_input:ip"
        ])

    playbook_input_ip = phantom.collect2(container=container, datapath=["playbook_input:ip"])

    parameters = []

    # build parameters list for 'create_ip_object' call
    for playbook_input_ip_item in playbook_input_ip:
        if location_formatted_string is not None:
            parameters.append({
                "location": location_formatted_string,
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get data", parameters=parameters, name="create_ip_object", assets=["http_firewall"], callback=block_traffic_from_ip)

    return


@phantom.playbook_block()
def block_traffic_from_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("block_traffic_from_ip() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    location_formatted_string = phantom.format(
        container=container,
        template="""webconsole/APIController?SecureStorageMasterKey=Passw0rd@12345&reqxml=<Request><Login><Username>API admin</Username><Password>7tE4s8)TTV</Password></Login><Set operation='add'><FirewallRule transactionid=\"\"><Name>BlockTrafficFromIP{0}</Name><Description>Block all traffic from IP-address {0}</Description><IPFamily>IPv4</IPFamily><Status>Enable</Status><Position>Top</Position><PolicyType>Network</PolicyType><NetworkPolicy><Action>Drop</Action><LogTraffic>Enable</LogTraffic><SkipLocalDestined>Disable</SkipLocalDestined><Schedule>All The Time</Schedule><SourceNetworks><Network>{0}</Network></SourceNetworks></NetworkPolicy></FirewallRule></Set></Request>""",
        parameters=[
            "playbook_input:ip"
        ])

    playbook_input_ip = phantom.collect2(container=container, datapath=["playbook_input:ip"])

    parameters = []

    # build parameters list for 'block_traffic_from_ip' call
    for playbook_input_ip_item in playbook_input_ip:
        if location_formatted_string is not None:
            parameters.append({
                "location": location_formatted_string,
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get data", parameters=parameters, name="block_traffic_from_ip", assets=["http_firewall"], callback=block_traffic_to_ip)

    return


@phantom.playbook_block()
def block_traffic_to_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("block_traffic_to_ip() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    location_formatted_string = phantom.format(
        container=container,
        template="""webconsole/APIController?SecureStorageMasterKey=Passw0rd@12345&reqxml=<Request><Login><Username>API admin</Username><Password>7tE4s8)TTV</Password></Login><Set operation='add'><FirewallRule transactionid=\"\"><Name>BlockTrafficToIP{0}</Name><Description>Block all traffic to IP-address {0}</Description><IPFamily>IPv4</IPFamily><Status>Enable</Status><Position>Top</Position><PolicyType>Network</PolicyType><NetworkPolicy><Action>Drop</Action><LogTraffic>Enable</LogTraffic><SkipLocalDestined>Disable</SkipLocalDestined><Schedule>All The Time</Schedule><DestinationNetworks><Network>{0}</Network></DestinationNetworks></NetworkPolicy></FirewallRule></Set></Request>""",
        parameters=[
            "playbook_input:ip"
        ])

    playbook_input_ip = phantom.collect2(container=container, datapath=["playbook_input:ip"])

    parameters = []

    # build parameters list for 'block_traffic_to_ip' call
    for playbook_input_ip_item in playbook_input_ip:
        if location_formatted_string is not None:
            parameters.append({
                "location": location_formatted_string,
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get data", parameters=parameters, name="block_traffic_to_ip", assets=["http_firewall"], callback=format_block_ip_comment)

    return


@phantom.playbook_block()
def format_block_ip_comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_block_ip_comment() called")

    template = """Malicious IP address ({0}) blocked in firewall"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_input:ip"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_block_ip_comment")

    comment_block_ip(container=container)

    return


@phantom.playbook_block()
def comment_block_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("comment_block_ip() called")

    format_block_ip_comment = phantom.get_format_data(name="format_block_ip_comment")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=format_block_ip_comment)

    join_format_incident_info_1(container=container)

    return


@phantom.playbook_block()
def comment_file_retrieve(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("comment_file_retrieve() called")

    format_file_content = phantom.get_format_data(name="format_file_content")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="The malicious file has been retrieved for analysis. Can be found under \"Notes\"")
    phantom.add_note(container=container, content=format_file_content, note_format="markdown", note_type="general")

    delete_file(container=container)

    return


@phantom.playbook_block()
def comment_file_deletion(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("comment_file_deletion() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="The malicious file has been deleted from the host")

    join_format_incident_info_1(container=container)

    return


@phantom.playbook_block()
def join_format_incident_info_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_format_incident_info_1() called")

    if phantom.completed(action_names=["hunt_ip_splunk", "block_traffic_to_ip", "delete_file"]):
        # call connected block "format_incident_info_1"
        format_incident_info_1(container=container, handle=handle)

    return


@phantom.playbook_block()
def format_incident_info_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_incident_info_1() called")

    hunt_ip_splunk_result_data = phantom.collect2(container=container, datapath=["hunt_ip_splunk:action_result.data.*.host"], action_results=results)

    hunt_ip_splunk_result_item_0 = [item[0] for item in hunt_ip_splunk_result_data]

    format_incident_info_1__status = None
    format_incident_info_1__format = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    phantom.debug("format_incident_info() called")
    if hunt_ip_splunk_result_item_0 != "":
        template = """Traffic confirmed to following malicious IP addresses: {0}\n\nThe following hosts communicated with the malicious IP addresses: {1}\n\nThe following files were correlated to the communication: {2}\n\nRemediation actions taken:\n- All communication has been blocked in firewall: True\n\n- All malicious files have been removed from the hosts: True"""
        # parameter list for template variable replacement
        parameters = [
            "playbook_input:ip",
            "hunt_ip_splunk:action_result.data.*.host",
            "correlate_traffic_to_process:action_result.data.*.malicious_FilePath"
        ]
        format_incident_info_1__status = True
    else:
        template = ""
        parameters = []
        format_incident_info_1__status = False
    
    format_incident_info_1__format = phantom.format(container=container, template=template, parameters=parameters, name="format_incident_info")
    phantom.debug(format_incident_info_1__format)
    

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="format_incident_info_1:status", value=json.dumps(format_incident_info_1__status))
    phantom.save_run_data(key="format_incident_info_1:format", value=json.dumps(format_incident_info_1__format))

    return


@phantom.playbook_block()
def format_file_content(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_file_content() called")

    template = """# File content\n-----------------------------------------\n{0}\n-----------------------------------------"""

    # parameter list for template variable replacement
    parameters = [
        "get_file:action_result.data.*.std_out"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_file_content")

    comment_file_retrieve(container=container)

    return


@phantom.playbook_block()
def delete_file(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("delete_file() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    script_str_formatted_string = phantom.format(
        container=container,
        template="""Remove-Item {0} -Force\n""",
        parameters=[
            "correlate_traffic_to_process:action_result.data.*.malicious_FilePath"
        ])

    correlate_traffic_to_process_result_data = phantom.collect2(container=container, datapath=["correlate_traffic_to_process:action_result.data.*.malicious_FilePath","correlate_traffic_to_process:action_result.parameter.context.artifact_id"], action_results=results)
    hunt_ip_splunk_result_data = phantom.collect2(container=container, datapath=["hunt_ip_splunk:action_result.data.*.host","hunt_ip_splunk:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'delete_file' call
    for correlate_traffic_to_process_result_item in correlate_traffic_to_process_result_data:
        for hunt_ip_splunk_result_item in hunt_ip_splunk_result_data:
            parameters.append({
                "script_str": script_str_formatted_string,
                "ip_hostname": hunt_ip_splunk_result_item[0],
                "context": {'artifact_id': hunt_ip_splunk_result_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run script", parameters=parameters, name="delete_file", assets=["winrm"], callback=comment_file_deletion)

    return


@phantom.playbook_block()
def get_file(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_file() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    script_str_formatted_string = phantom.format(
        container=container,
        template="""cat {0}\n""",
        parameters=[
            "correlate_traffic_to_process:action_result.data.*.malicious_FilePath"
        ])

    correlate_traffic_to_process_result_data = phantom.collect2(container=container, datapath=["correlate_traffic_to_process:action_result.data.*.malicious_FilePath","correlate_traffic_to_process:action_result.parameter.context.artifact_id"], action_results=results)
    hunt_ip_splunk_result_data = phantom.collect2(container=container, datapath=["hunt_ip_splunk:action_result.data.*.host","hunt_ip_splunk:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'get_file' call
    for correlate_traffic_to_process_result_item in correlate_traffic_to_process_result_data:
        for hunt_ip_splunk_result_item in hunt_ip_splunk_result_data:
            parameters.append({
                "script_str": script_str_formatted_string,
                "ip_hostname": hunt_ip_splunk_result_item[0],
                "context": {'artifact_id': hunt_ip_splunk_result_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run script", parameters=parameters, name="get_file", assets=["winrm"], callback=format_file_content)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    format_incident_info_1__format = json.loads(_ if (_ := phantom.get_run_data(key="format_incident_info_1:format")) != "" else "null")  # pylint: disable=used-before-assignment
    format_incident_info_1__status = json.loads(_ if (_ := phantom.get_run_data(key="format_incident_info_1:status")) != "" else "null")  # pylint: disable=used-before-assignment

    output = {
        "incident_format": format_incident_info_1__format,
        "incident_status_code": format_incident_info_1__status,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_playbook_output_data(output=output)

    return