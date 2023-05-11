"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'whois_ip_1' block
    whois_ip_1(container=container)
    # call 'create_firewall_ip_object' block
    create_firewall_ip_object(container=container)

    return

@phantom.playbook_block()
def geolocate_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("geolocate_ip_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.src","artifact:*.id"])

    parameters = []

    # build parameters list for 'geolocate_ip_1' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "ip": container_artifact_item[0],
                "context": {'artifact_id': container_artifact_item[1]},
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
def whois_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("whois_ip_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.src","artifact:*.id"])

    parameters = []

    # build parameters list for 'whois_ip_1' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "ip": container_artifact_item[0],
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("whois ip", parameters=parameters, name="whois_ip_1", assets=["whois"], callback=whois_ip_1_callback)

    return


@phantom.playbook_block()
def whois_ip_1_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("whois_ip_1_callback() called")

    
    format_whois_result(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    decision_public_or_private_ip(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


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
def format_whois_result(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_whois_result() called")

    template = """WHOIS ip resolved with the following message:\n\n{0}"""

    # parameter list for template variable replacement
    parameters = [
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
def decision_public_or_private_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_public_or_private_ip() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["is already defined as Private-Use Networks via RFC 1918.", "in", "whois_ip_1:action_result.message"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        format_private_address(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    format_public_ip(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def comment_private_address(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("comment_private_address() called")

    format_private_address = phantom.get_format_data(name="format_private_address")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=format_private_address)

    get_hostname_from_ip(container=container)

    return


@phantom.playbook_block()
def format_private_address(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_private_address() called")

    template = """Potential brute force attack originates from internal IP-address {0}. Starting internal actions."""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.src"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_private_address")

    comment_private_address(container=container)

    return


@phantom.playbook_block()
def format_public_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_public_ip() called")

    template = """Potential brute force attack originates from public IP-address {0}. Starting public IP investigations.\n"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.src"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_public_ip")

    comment_public_address(container=container)

    return


@phantom.playbook_block()
def comment_public_address(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("comment_public_address() called")

    format_public_ip = phantom.get_format_data(name="format_public_ip")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=format_public_ip)

    geolocate_ip_1(container=container)
    ip_reputation_1(container=container)

    return


@phantom.playbook_block()
def format_geolocate_result(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_geolocate_result() called")

    template = """MaxMind geolocate result for {0}:\n\nCountry: {1} ({2}), {3}\nState: {4}\nCity: {5}\nOrg: {6}\n"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.src",
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

    join_format_external_attack_summary(container=container)

    return


@phantom.playbook_block()
def ip_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("ip_reputation_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.src","artifact:*.id"])

    parameters = []

    # build parameters list for 'ip_reputation_1' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "ip": container_artifact_item[0],
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("ip reputation", parameters=parameters, name="ip_reputation_1", assets=["virustotal"], callback=decision_ip_reputation_result)

    return


@phantom.playbook_block()
def format_ip_reputation_result(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_ip_reputation_result() called")

    template = """VirusTotal IP reputation check for {0}:\n\n{1}"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.src",
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

    join_format_external_attack_summary(container=container)

    return


@phantom.playbook_block()
def decision_ip_reputation_result(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_ip_reputation_result() called")

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

    template = """IP-address {0} not found in VirusTotal database. \n"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.src"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_ip_reputation_no_result")

    join_format_external_attack_summary(container=container)

    return


@phantom.playbook_block()
def get_hostname_from_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_hostname_from_ip() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    query_formatted_string = phantom.format(
        container=container,
        template="""sourcetype=\"WinEventLog:Microsoft-Windows-Sysmon/Operational\" EventCode=22 QueryResults=*{0}* | dedup host | table host""",
        parameters=[
            "artifact:*.cef.src"
        ])

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.src","artifact:*.id"])

    parameters = []

    # build parameters list for 'get_hostname_from_ip' call
    for container_artifact_item in container_artifact_data:
        if query_formatted_string is not None:
            parameters.append({
                "query": query_formatted_string,
                "command": "search",
                "start_time": "-24h",
                "search_mode": "smart",
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="get_hostname_from_ip", assets=["splunk"], callback=format_hostname_from_ip_result)

    return


@phantom.playbook_block()
def format_hostname_from_ip_result(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_hostname_from_ip_result() called")

    template = """Internal IP-address {0} belongs to host {1}. Investigate host for indicators of compromise and take necessary actions."""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.src",
        "get_hostname_from_ip:action_result.data.*.host"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_hostname_from_ip_result")

    comment_hostname_from_ip_result(container=container)

    return


@phantom.playbook_block()
def comment_hostname_from_ip_result(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("comment_hostname_from_ip_result() called")

    format_hostname_from_ip_result = phantom.get_format_data(name="format_hostname_from_ip_result")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=format_hostname_from_ip_result)

    prompt_for_endpoint_analysis(container=container)

    return


@phantom.playbook_block()
def create_firewall_ip_object(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("create_firewall_ip_object() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    location_formatted_string = phantom.format(
        container=container,
        template="""webconsole/APIController?SecureStorageMasterKey=Passw0rd@12345&reqxml=<Request><Login><Username>API admin</Username><Password>7tE4s8)TTV</Password></Login><Set><IPHost><Name>{0}</Name><IPFamily>IPv4</IPFamily><HostType>IP</HostType><IPAddress>{0}</IPAddress></IPHost></Set></Request>\n""",
        parameters=[
            "artifact:*.cef.src"
        ])

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.src","artifact:*.id"])

    parameters = []

    # build parameters list for 'create_firewall_ip_object' call
    for container_artifact_item in container_artifact_data:
        if location_formatted_string is not None:
            parameters.append({
                "location": location_formatted_string,
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get data", parameters=parameters, name="create_firewall_ip_object", assets=["http_firewall"], callback=create_firewall_drop_rule)

    return


@phantom.playbook_block()
def create_firewall_drop_rule(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("create_firewall_drop_rule() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    location_formatted_string = phantom.format(
        container=container,
        template="""webconsole/APIController?SecureStorageMasterKey=Passw0rd@12345&reqxml=<Request><Login><Username>API admin</Username><Password>7tE4s8)TTV</Password></Login><Set operation='add'><FirewallRule transactionid=\"\"><Name>BlockIp{0}</Name><Description>Block all traffic from IP-address {0}</Description><IPFamily>IPv4</IPFamily><Status>Enable</Status><Position>Top</Position><PolicyType>Network</PolicyType><NetworkPolicy><Action>Drop</Action><LogTraffic>Enable</LogTraffic><SkipLocalDestined>Disable</SkipLocalDestined><Schedule>All The Time</Schedule><SourceNetworks><Network>{0}</Network></SourceNetworks></NetworkPolicy></FirewallRule></Set></Request>\n""",
        parameters=[
            "artifact:*.cef.src"
        ])

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.src","artifact:*.id"])

    parameters = []

    # build parameters list for 'create_firewall_drop_rule' call
    for container_artifact_item in container_artifact_data:
        if location_formatted_string is not None:
            parameters.append({
                "location": location_formatted_string,
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get data", parameters=parameters, name="create_firewall_drop_rule", assets=["http_firewall"], callback=format_firewall_rule_created)

    return


@phantom.playbook_block()
def join_prompt_close_incident_after_internal_attack(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_prompt_close_incident_after_internal_attack() called")

    if phantom.completed(action_names=["prompt_for_endpoint_analysis"], playbook_names=["playbook_endpoint_analysis_1"]):
        # call connected block "prompt_close_incident_after_internal_attack"
        prompt_close_incident_after_internal_attack(container=container, handle=handle)

    return


@phantom.playbook_block()
def prompt_close_incident_after_internal_attack(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("prompt_close_incident_after_internal_attack() called")

    # set user and message variables for phantom.prompt call

    user = "soar_local_admin"
    role = None
    message = """Performed endpoint analysis on internal host {0} ({1}): {2}.\n\nVerify that the potential threat is contained, normal operations are resumed, and that the incident can be closed."""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.src",
        "get_hostname_from_ip:action_result.data.*.host",
        "prompt_for_endpoint_analysis:action_result.summary.responses.0"
    ]

    # responses
    response_types = [
        {
            "prompt": "Do you want to close the incident?",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No"
                ],
            },
        }
    ]

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=30, name="prompt_close_incident_after_internal_attack", parameters=parameters, response_types=response_types, callback=decision_close_incident_after_internal_attack)

    return


@phantom.playbook_block()
def format_firewall_rule_created(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_firewall_rule_created() called")

    template = """Brute Force Attack detected from IP {0} against user \"{1}\" in Sophos Firewall. Created firewall block rule against host to mitigate attack. \n\nConsider changing password for user \"{1}\" to protect against brute force attacks."""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.src",
        "artifact:*.cef.user"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_firewall_rule_created")

    comment_firewall_rule_created(container=container)

    return


@phantom.playbook_block()
def comment_firewall_rule_created(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("comment_firewall_rule_created() called")

    format_firewall_rule_created = phantom.get_format_data(name="format_firewall_rule_created")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=format_firewall_rule_created)

    return


@phantom.playbook_block()
def decision_close_incident_after_internal_attack(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_close_incident_after_internal_attack() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["prompt_close_incident_after_internal_attack:action_result.summary.responses.0", "==", "Yes"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        close_incident_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def prompt_close_incident_after_external_attack(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("prompt_close_incident_after_external_attack() called")

    # set user and message variables for phantom.prompt call

    user = "soar_local_admin"
    role = None
    message = """Performed investigation against public IP {1}.\n\nVerify that the potential threat is contained, normal operations are resumed, and that the incident can be closed."""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.src"
    ]

    # responses
    response_types = [
        {
            "prompt": "Do you want to close the incident?",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No"
                ],
            },
        }
    ]

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=30, name="prompt_close_incident_after_external_attack", parameters=parameters, response_types=response_types, callback=decision_close_incident_after_external_attack)

    return


@phantom.playbook_block()
def decision_close_incident_after_external_attack(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_close_incident_after_external_attack() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["prompt_close_incident_after_external_attack:action_result.summary.responses.0", "==", "Yes"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        close_incident(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def close_incident(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("close_incident() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="Case closed by analyst")
    phantom.set_status(container=container, status="closed")

    container = phantom.get_container(container.get('id', None))

    return


@phantom.playbook_block()
def join_format_external_attack_summary(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_format_external_attack_summary() called")

    if phantom.completed(action_names=["geolocate_ip_1", "ip_reputation_1"]):
        # call connected block "format_external_attack_summary"
        format_external_attack_summary(container=container, handle=handle)

    return


@phantom.playbook_block()
def format_external_attack_summary(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_external_attack_summary() called")

    template = """{0}\n{1}\n{2}\n\nInvestigate source of attack and take necessary actions."""

    # parameter list for template variable replacement
    parameters = [
        "format_geolocate_result:formatted_data",
        "format_ip_reputation_result:formatted_data",
        "format_ip_reputation_no_result:formatted_data"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_external_attack_summary")

    comment_external_attack_summary(container=container)

    return


@phantom.playbook_block()
def comment_external_attack_summary(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("comment_external_attack_summary() called")

    format_external_attack_summary = phantom.get_format_data(name="format_external_attack_summary")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=format_external_attack_summary)

    prompt_close_incident_after_external_attack(container=container)

    return


@phantom.playbook_block()
def prompt_for_endpoint_analysis(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("prompt_for_endpoint_analysis() called")

    # set user and message variables for phantom.prompt call

    user = "soar_local_admin"
    role = None
    message = """Potential brute force attack originates from internal IP-address {0} ({1}).\n\nThe endpoint might be compromised and being used for adversary actions. The endpoint should be investigated for indicators of compromise and necessary actions should be taken if indicators are found."""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.src",
        "get_hostname_from_ip:action_result.data.*.host"
    ]

    # responses
    response_types = [
        {
            "prompt": "Do you want to perform endpoint analysis to look for IOC?",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No"
                ],
            },
        }
    ]

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=30, name="prompt_for_endpoint_analysis", parameters=parameters, response_types=response_types, callback=decicion_endpoint_analysis)

    return


@phantom.playbook_block()
def decicion_endpoint_analysis(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decicion_endpoint_analysis() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["prompt_for_endpoint_analysis:action_result.summary.responses.0", "==", "Yes"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        playbook_endpoint_analysis_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    join_prompt_close_incident_after_internal_attack(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def format_endpoint_analysis_finished(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_endpoint_analysis_finished() called")

    template = """Endpoint analysis of host {0} finished.\n"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.src"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_endpoint_analysis_finished")

    comment_endpoint_analysis_finished(container=container)

    return


@phantom.playbook_block()
def comment_endpoint_analysis_finished(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("comment_endpoint_analysis_finished() called")

    format_endpoint_analysis_finished = phantom.get_format_data(name="format_endpoint_analysis_finished")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=format_endpoint_analysis_finished)

    join_prompt_close_incident_after_internal_attack(container=container)

    return


@phantom.playbook_block()
def playbook_endpoint_analysis_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbook_endpoint_analysis_1() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.src"])

    container_artifact_cef_item_0 = [item[0] for item in container_artifact_data]

    inputs = {
        "host_ip": container_artifact_cef_item_0,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/Endpoint Analysis", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/Endpoint Analysis", container=container, name="playbook_endpoint_analysis_1", callback=format_endpoint_analysis_finished, inputs=inputs)

    return


@phantom.playbook_block()
def close_incident_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("close_incident_1() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="Case closed by analyst")
    phantom.set_status(container=container, status="closed")

    container = phantom.get_container(container.get('id', None))

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    return