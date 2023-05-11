"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'decision_hash_exist' block
    decision_hash_exist(container=container)
    # call 'convert_av_action_id_to_name' block
    convert_av_action_id_to_name(container=container)

    return

@phantom.playbook_block()
def scan_hash(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("scan_hash() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.Hashes_sha1","artifact:*.id"])

    parameters = []

    # build parameters list for 'scan_hash' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "hash": container_artifact_item[0],
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("file reputation", parameters=parameters, name="scan_hash", assets=["virustotal"], callback=get_detection_ratio)

    return


@phantom.playbook_block()
def decision_action_eventcode(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_action_eventcode() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.Action_EventCode", "==", None]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        comment_no_action(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2
    found_match_2 = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.Action_EventCode", "==", 1117]
        ])

    # call connected blocks if condition 2 matched
    if found_match_2:
        comment_successful_action_and_lower_severity(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 3
    found_match_3 = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.Action_EventCode", "==", 1118]
        ])

    # call connected blocks if condition 3 matched
    if found_match_3:
        comment_failed_not_critically(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 4
    comment_critical_failure_and_raise_severity(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def comment_no_action(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("comment_no_action() called")

    ################################################################################
    # There was no action Event code in the artifact.  Severity is set to medium
    ################################################################################

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="Antivirus action event code is missing")
    phantom.set_severity(container=container, severity="low")

    container = phantom.get_container(container.get('id', None))

    join_comment_start_full_scan(container=container)

    return


@phantom.playbook_block()
def comment_critical_failure_and_raise_severity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("comment_critical_failure_and_raise_severity() called")

    ################################################################################
    # The action taken to remediate the malware failed critically. Severity is set 
    # to high
    ################################################################################

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="Antivirus failed critically")
    phantom.set_severity(container=container, severity="high")

    container = phantom.get_container(container.get('id', None))

    prompt_security_analyst_after_critical_av_failure(container=container)
    join_comment_start_full_scan(container=container)

    return


@phantom.playbook_block()
def comment_successful_action_and_lower_severity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("comment_successful_action_and_lower_severity() called")

    ################################################################################
    # The action to remediate the malware was taken successfully. Severity is set 
    # to low
    ################################################################################

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="Antivirus action completed successfully")
    phantom.set_severity(container=container, severity="low")

    container = phantom.get_container(container.get('id', None))

    join_comment_start_full_scan(container=container)

    return


@phantom.playbook_block()
def comment_failed_not_critically(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("comment_failed_not_critically() called")

    ################################################################################
    # The action taken to remediate the malware failed. However not critically. Severity 
    # is set to medium
    ################################################################################

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="Antivirus action failed, but not critical")
    phantom.set_severity(container=container, severity="high")

    join_comment_start_full_scan(container=container)

    return


@phantom.playbook_block()
def decision_hash_exist(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_hash_exist() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.Hashes_sha1", "!=", ""]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        comment_hash_exist(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    comment_hash_not_exist(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def comment_hash_exist(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("comment_hash_exist() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="Sha1 hash exist")

    scan_hash(container=container)

    return


@phantom.playbook_block()
def comment_hash_not_exist(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("comment_hash_not_exist() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="Sha1 hash does not exist")

    return


@phantom.playbook_block()
def get_detection_ratio(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_detection_ratio() called")

    scan_hash_result_data = phantom.collect2(container=container, datapath=["scan_hash:action_result.summary.positives","scan_hash:action_result.summary.total_scans"], action_results=results)

    scan_hash_summary_positives = [item[0] for item in scan_hash_result_data]
    scan_hash_summary_total_scans = [item[1] for item in scan_hash_result_data]

    get_detection_ratio__result = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    
    get_detection_ratio__result = int((round(scan_hash_summary_positives[0] / scan_hash_summary_total_scans[0],2) * 100))
    
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="get_detection_ratio:result", value=json.dumps(get_detection_ratio__result))

    format_ratio(container=container)

    return


@phantom.playbook_block()
def comment_detection_ratio(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("comment_detection_ratio() called")

    ################################################################################
    # At least half of all scanners flagged the file. Next step is to detonate the 
    # file in an isolated sandbox
    ################################################################################

    format_ratio = phantom.get_format_data(name="format_ratio")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=format_ratio)

    sandbox_detonation(container=container)

    return


@phantom.playbook_block()
def prompt_security_analyst_after_critical_av_failure(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("prompt_security_analyst_after_critical_av_failure() called")

    # set user and message variables for phantom.prompt call

    user = "soar_local_admin"
    role = None
    message = """Antivirus failed critically. Further investigation, containment and remediation may be needed"""

    # parameter list for template variable replacement
    parameters = []

    # responses
    response_types = [
        {
            "prompt": "Acknowledge?",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No"
                ],
            },
        }
    ]

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=45, name="prompt_security_analyst_after_critical_av_failure", parameters=parameters, response_types=response_types)

    return


@phantom.playbook_block()
def join_comment_start_full_scan(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_comment_start_full_scan() called")

    # call connected block "comment_start_full_scan"
    comment_start_full_scan(container=container, handle=handle)

    return


@phantom.playbook_block()
def comment_start_full_scan(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("comment_start_full_scan() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="Starting full scan")

    full_scan(container=container)

    return


@phantom.playbook_block()
def full_scan(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("full_scan() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Starting full scan on host
    ################################################################################

    parameters = []

    parameters.append({
        "script_str": "Start-MpScan -ScanType QuickScan | ConvertTo-Json",
        "ip_hostname": "10.50.0.4",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run script", parameters=parameters, name="full_scan", assets=["winrm"], callback=format_script)

    return


@phantom.playbook_block()
def get_full_scan_result(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_full_scan_result() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    format_script = phantom.get_format_data(name="format_script")

    parameters = []

    parameters.append({
        "script_str": format_script,
        "ip_hostname": "10.50.0.4",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run script", parameters=parameters, name="get_full_scan_result", assets=["winrm"], callback=get_threat_status)

    return


@phantom.playbook_block()
def format_ratio(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_ratio() called")

    template = """Detection ratio: {0}\n"""

    # parameter list for template variable replacement
    parameters = [
        "get_detection_ratio:custom_function:result"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_ratio")

    comment_detection_ratio(container=container)

    return


@phantom.playbook_block()
def format_script(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_script() called")

    ################################################################################
    # Script configured to retrieve full scan result
    ################################################################################

    template = """Get-MpThreatDetection -ThreatID {0} | Sort-Object -Property LastThreatStatusChangeTime -Descending | select -first 1"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.ID"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_script")

    get_full_scan_result(container=container)

    return


@phantom.playbook_block()
def get_threat_status(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_threat_status() called")

    get_full_scan_result_result_data = phantom.collect2(container=container, datapath=["get_full_scan_result:action_result.data.*.std_out"], action_results=results)

    get_full_scan_result_result_item_0 = [item[0] for item in get_full_scan_result_result_data]

    get_threat_status__id = None
    get_threat_status__name = None
    get_threat_status__sucess_status = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here .....
    
    # Custom imports
    import re
    
    
    # ID to name dictionary
    id_to_name = {
        0   : "Unknown",
        1   : "Detected",
        2   : "Cleaned",
        3   : "Quarantined",
        4   : "Removed",
        5   : "Allowed",
        6   : "Blocked",
        102 : "QuarantineFailed",
        103 : "RemoveFailed",
        104 : "AllowFailed",
        105 : "Abondoned",
        106 : "Unknown",
        107 : "BlockedFailed"
    }
    # Threat status IDs indicating success
    threatID_success = [2, 3, 4, 5, 6, 106]
    
    num = re.findall(r'ThreatStatusID\s*:\s*(\d+)', get_full_scan_result_result_item_0[0])
    get_threat_status__id = int(num[0])
    get_threat_status__name = id_to_name[get_threat_status__id]
    get_threat_status__sucess_status =  get_threat_status__id in threatID_success
    

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="get_threat_status:id", value=json.dumps(get_threat_status__id))
    phantom.save_run_data(key="get_threat_status:name", value=json.dumps(get_threat_status__name))
    phantom.save_run_data(key="get_threat_status:sucess_status", value=json.dumps(get_threat_status__sucess_status))

    decision_threat_status(container=container)

    return


@phantom.playbook_block()
def decision_threat_status(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_threat_status() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["get_threat_status:custom_function:sucess_status", "==", True]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        comment_success_and_close(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    comment_remediation_fail_and_raise_severity(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def comment_remediation_fail_and_raise_severity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("comment_remediation_fail_and_raise_severity() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="The remediation of the malware failed")
    phantom.set_severity(container=container, severity="high")

    container = phantom.get_container(container.get('id', None))

    prompt_close_after_remediation_fail(container=container)

    return


@phantom.playbook_block()
def prompt_close_after_remediation_fail(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("prompt_close_after_remediation_fail() called")

    # set user and message variables for phantom.prompt call

    user = "soar_local_admin"
    role = None
    message = """Malware remediation has failed\n\nAV action event code: {0} ({1})\nFull scan initiated: True\nThreat status after full scan: {2} ({3})\n"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.Action_EventCode",
        "convert_av_action_id_to_name:custom_function:symbolic_name",
        "get_threat_status:custom_function:id",
        "get_threat_status:custom_function:name"
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

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=30, name="prompt_close_after_remediation_fail", parameters=parameters, response_types=response_types, callback=decision_close_after_remediation_fail)

    return


@phantom.playbook_block()
def convert_av_action_id_to_name(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("convert_av_action_id_to_name() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.Action_EventCode"])

    container_artifact_cef_item_0 = [item[0] for item in container_artifact_data]

    convert_av_action_id_to_name__symbolic_name = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    id_to_name = {
        1117 : "MALWAREPROTECTION_STATE_MALWARE_ACTION_TAKEN",
        1118 : "MALWAREPROTECTION_STATE_MALWARE_ACTION_FAILED",
        1119 : "MALWAREPROTECTION_STATE_MALWARE_ACTION_CRITICALLY_FAILED"
    }
    
    convert_av_action_id_to_name__symbolic_name = id_to_name[int(container_artifact_cef_item_0[0])]
    phantom.debug(type(convert_av_action_id_to_name__symbolic_name))
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="convert_av_action_id_to_name:symbolic_name", value=json.dumps(convert_av_action_id_to_name__symbolic_name))

    decision_action_eventcode(container=container)

    return


@phantom.playbook_block()
def decision_close_after_remediation_fail(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_close_after_remediation_fail() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["prompt_close_after_remediation_fail:action_result.summary.{summaryVar}", "==", "Yes"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        comment_yes_and_close(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    comment_no(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def comment_success_and_close(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("comment_success_and_close() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="The malware was remediated successfully")
    phantom.set_status(container=container, status="closed")

    container = phantom.get_container(container.get('id', None))

    return


@phantom.playbook_block()
def comment_yes_and_close(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("comment_yes_and_close() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="Analyst wants to close incident")
    phantom.set_status(container=container, status="closed")

    container = phantom.get_container(container.get('id', None))

    return


@phantom.playbook_block()
def comment_no(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("comment_no() called")

    ################################################################################
    # Severity is set to medium
    ################################################################################

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="Analyst wants to keep incident open")

    container = phantom.get_container(container.get('id', None))

    return


@phantom.playbook_block()
def sandbox_detonation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("sandbox_detonation() called")

    sandbox_detonation__type = None
    sandbox_detonation__environment_description = None
    sandbox_detonation__tags = None
    sandbox_detonation__vx_family = None
    sandbox_detonation__threat_score = None
    sandbox_detonation__threat_level = None
    sandbox_detonation__verdict = None
    sandbox_detonation__sha256 = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    import requests
    url = 'https://www.hybrid-analysis.com/api/v2/search/hash'
    headers = {
        'accept': 'application/json',
        'user-agent': 'Falcon Sandbox',
        'api-key': '1sj0wf1j9b10738bj3xnbph2f7df5fe7q9tjhws1af1f00f3xc9k8wgy2cdb8467'
    }
    data = {
        'hash': '3395856ce81f2b7382dee72602f798b642f14140'   
    }
    response = requests.post(url, headers=headers, data=data)
    sandbox_detonation__sha256 = response.json()[0]['sha256']
    
    url = f'https://www.hybrid-analysis.com/api/v2/overview/{sandbox_detonation__sha256}'
    response = requests.get(url, headers=headers)
    reportID = response.json()["reports"][0]
    
    url = f'https://www.hybrid-analysis.com/api/v2/report/{reportID}/summary'

    response = requests.get(url, headers=headers).json()
    #phantom.debug(response)
    
    
    sandbox_detonation__type = response['type']
    sandbox_detonation__environment_description = response['environment_description']
    sandbox_detonation__tags = response['tags']
    sandbox_detonation__vx_family = response['vx_family']
    sandbox_detonation__threat_score = response['threat_score']
    sandbox_detonation__threat_level = response['threat_level']
    sandbox_detonation__verdict = response['verdict']
    


    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="sandbox_detonation:type", value=json.dumps(sandbox_detonation__type))
    phantom.save_run_data(key="sandbox_detonation:environment_description", value=json.dumps(sandbox_detonation__environment_description))
    phantom.save_run_data(key="sandbox_detonation:tags", value=json.dumps(sandbox_detonation__tags))
    phantom.save_run_data(key="sandbox_detonation:vx_family", value=json.dumps(sandbox_detonation__vx_family))
    phantom.save_run_data(key="sandbox_detonation:threat_score", value=json.dumps(sandbox_detonation__threat_score))
    phantom.save_run_data(key="sandbox_detonation:threat_level", value=json.dumps(sandbox_detonation__threat_level))
    phantom.save_run_data(key="sandbox_detonation:verdict", value=json.dumps(sandbox_detonation__verdict))
    phantom.save_run_data(key="sandbox_detonation:sha256", value=json.dumps(sandbox_detonation__sha256))

    get_sample_name(container=container)

    return


@phantom.playbook_block()
def format_malware_report_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_malware_report_1() called")

    template = """# Analysis report\nSample name: *{0}*\n\n| Field | Value |\n| -------- | -------- |\n| Verdict | **{4}** |\n| Score | {5} |\n| Threat level | {8} |\n| Malware family | {6} | \n| Type | {7} |\n| SHA1 | {1} |\n| SHA256 | {2} |\n| Environment description | {9} |\n| Tags | {3} |"""

    # parameter list for template variable replacement
    parameters = [
        "get_sample_name:custom_function:sample_name",
        "artifact:*.cef.Hashes_sha1",
        "sandbox_detonation:custom_function:sha256",
        "sandbox_detonation:custom_function:tags",
        "sandbox_detonation:custom_function:verdict",
        "sandbox_detonation:custom_function:threat_score",
        "sandbox_detonation:custom_function:vx_family",
        "sandbox_detonation:custom_function:type",
        "sandbox_detonation:custom_function:threat_level",
        "sandbox_detonation:custom_function:environment_description"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_malware_report_1")

    write_malware_report(container=container)

    return


@phantom.playbook_block()
def write_malware_report(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("write_malware_report() called")

    format_malware_report_1 = phantom.get_format_data(name="format_malware_report_1")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="Malware detonation completed. Report can be found under \"Notes\"")
    phantom.add_note(container=container, content=format_malware_report_1, note_format="markdown", note_type="general")

    return


@phantom.playbook_block()
def get_sample_name(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_sample_name() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.Path"])

    container_artifact_cef_item_0 = [item[0] for item in container_artifact_data]

    get_sample_name__sample_name = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    get_sample_name__sample_name = container_artifact_cef_item_0[0].split('\\')[-1]

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="get_sample_name:sample_name", value=json.dumps(get_sample_name__sample_name))

    format_malware_report_1(container=container)

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