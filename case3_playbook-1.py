"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'split_ioc_artifacts' block
    split_ioc_artifacts(container=container)

    return

@phantom.playbook_block()
def comment_ip_ioc(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("comment_ip_ioc() called")

    format_ip_ioc = phantom.get_format_data(name="format_ip_ioc")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=format_ip_ioc)

    hunt_iocs_ip(container=container)

    return


@phantom.playbook_block()
def comment_hash_ioc(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("comment_hash_ioc() called")

    format_hash_ioc = phantom.get_format_data(name="format_hash_ioc")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=format_hash_ioc)

    hunt_iocs_hash(container=container)

    return


@phantom.playbook_block()
def comment_domain_ioc(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("comment_domain_ioc() called")

    format_domain_ioc = phantom.get_format_data(name="format_domain_ioc")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=format_domain_ioc)

    hunt_iocs_domain(container=container)

    return


@phantom.playbook_block()
def hunt_iocs_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("hunt_iocs_ip() called")

    loop_over_artifacts__ioc = json.loads(_ if (_ := phantom.get_run_data(key="loop_over_artifacts:ioc")) != "" else "null")  # pylint: disable=used-before-assignment

    inputs = {
        "ip": loop_over_artifacts__ioc,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/Hunt IOCs IP", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/Hunt IOCs IP", container=container, name="hunt_iocs_ip", callback=decision_found_ioc, inputs=inputs)

    return


@phantom.playbook_block()
def hunt_iocs_domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("hunt_iocs_domain() called")

    inputs = {}

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/Hunt IOCs domain", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/Hunt IOCs domain", container=container, name="hunt_iocs_domain", inputs=inputs)

    return


@phantom.playbook_block()
def hunt_iocs_hash(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("hunt_iocs_hash() called")

    inputs = {}

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/Hunt IOCs hash", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/Hunt IOCs hash", container=container, name="hunt_iocs_hash", inputs=inputs)

    return


@phantom.playbook_block()
def format_ip_ioc(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_ip_ioc() called")

    template = """IOC-list contained the following IP address: \"{0}\". Starting hunt for found IP.\n"""

    # parameter list for template variable replacement
    parameters = [
        "loop_over_artifacts:custom_function:ioc"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_ip_ioc")

    comment_ip_ioc(container=container)

    return


@phantom.playbook_block()
def format_hash_ioc(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_hash_ioc() called")

    template = """IOC-list contained the following hash: \"{0}\". Starting hunt for found hash.\n"""

    # parameter list for template variable replacement
    parameters = [
        "loop_over_artifacts:custom_function:ioc"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_hash_ioc")

    comment_hash_ioc(container=container)

    return


@phantom.playbook_block()
def format_domain_ioc(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_domain_ioc() called")

    template = """IOC-list contained the following domain: \"{0}\". Starting hunt for found domain.\n"""

    # parameter list for template variable replacement
    parameters = [
        "loop_over_artifacts:custom_function:ioc"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_domain_ioc")

    comment_domain_ioc(container=container)

    return


@phantom.playbook_block()
def split_ioc_artifacts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("split_ioc_artifacts() called")

    template = """%%\n{0},{1}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.ioc",
        "artifact:*.cef.type"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="split_ioc_artifacts")

    loop_over_artifacts(container=container)

    return


@phantom.playbook_block()
def loop_over_artifacts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("loop_over_artifacts() called")

    split_ioc_artifacts__as_list = phantom.get_format_data(name="split_ioc_artifacts__as_list")

    loop_over_artifacts__ioc = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    
    for i in range(len(split_ioc_artifacts__as_list)):
        if "ip" in split_ioc_artifacts__as_list[i]:
            loop_over_artifacts__ioc = split_ioc_artifacts__as_list[i].split(",")[0]
            phantom.save_run_data(key="loop_over_artifacts:ioc", value=json.dumps(loop_over_artifacts__ioc))
            format_ip_ioc(container=container)        
        elif "hash" in split_ioc_artifacts__as_list[i]:
            loop_over_artifacts__ioc = split_ioc_artifacts__as_list[i].split(",")[0]
            phantom.save_run_data(key="loop_over_artifacts:ioc", value=json.dumps(loop_over_artifacts__ioc))
            format_hash_ioc(container=container)
        elif "domain" in split_ioc_artifacts__as_list[i]:
            loop_over_artifacts__ioc = split_ioc_artifacts__as_list[i].split(",")[0]
            phantom.save_run_data(key="loop_over_artifacts:ioc", value=json.dumps(loop_over_artifacts__ioc))
            format_domain_ioc(container=container)
        else:
            loop_over_artifacts__ioc = split_ioc_artifacts__as_list[i].split(",")[0]
            phantom.save_run_data(key="loop_over_artifacts:ioc", value=json.dumps(loop_over_artifacts__ioc))
            format_unknown_ioc(container=container)
    return

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="loop_over_artifacts:ioc", value=json.dumps(loop_over_artifacts__ioc))

    format_hash_ioc(container=container)
    format_ip_ioc(container=container)
    format_domain_ioc(container=container)
    format_unknown_ioc(container=container)

    return


@phantom.playbook_block()
def format_unknown_ioc(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_unknown_ioc() called")

    template = """IOC-list contained the following unknown IOC: \"{0}\". Skipping."""

    # parameter list for template variable replacement
    parameters = [
        "loop_over_artifacts:custom_function:ioc"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_unknown_ioc")

    comment_unknown_ioc(container=container)

    return


@phantom.playbook_block()
def comment_unknown_ioc(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("comment_unknown_ioc() called")

    format_unknown_ioc = phantom.get_format_data(name="format_unknown_ioc")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=format_unknown_ioc)

    return


@phantom.playbook_block()
def decision_found_ioc(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_found_ioc() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["playbook_hunt_iocs_ip_1:playbook_output:incident_status_code", "==", True]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        prompt_for_close(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    join_add_comment_and_close_case(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def prompt_for_close(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("prompt_for_close() called")

    # set user and message variables for phantom.prompt call

    user = "soar_local_admin"
    role = None
    message = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_hunt_iocs_ip_1:playbook_output:incident_format"
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

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=30, name="prompt_for_close", parameters=parameters, response_types=response_types, callback=decision_prompt_for_close)

    return


@phantom.playbook_block()
def join_add_comment_and_close_case(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_add_comment_and_close_case() called")

    if phantom.completed(playbook_names=["hunt_iocs_ip"], action_names=["prompt_for_close"]):
        # call connected block "add_comment_and_close_case"
        add_comment_and_close_case(container=container, handle=handle)

    return


@phantom.playbook_block()
def add_comment_and_close_case(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_comment_and_close_case() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="Closed by analyst")
    phantom.set_status(container=container, status="closed")

    container = phantom.get_container(container.get('id', None))

    return


@phantom.playbook_block()
def decision_prompt_for_close(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_prompt_for_close() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["prompt_for_close:action_result.summary.responses.0", "==", "Yes"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        join_add_comment_and_close_case(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    set_severity_to_high(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def set_severity_to_high(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("set_severity_to_high() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_severity(container=container, severity="high")

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